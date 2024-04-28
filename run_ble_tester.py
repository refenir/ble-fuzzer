import logging
import asyncio
import sys
import os
import subprocess
import json
import random
import copy
import requests
from binascii import hexlify

from bumble.device import Device, Peer
from bumble.host import Host
from bumble.gatt import show_services
from bumble.core import ProtocolError
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.transport import open_transport_or_link
from bumble.utils import AsyncRunner
from bumble.colors import color


class FuzzingTestCase:
    def __init__(self):
        self.seedQ = []
        self.failureQ = []
        self.num_iterations = 20
        self.coverage_before = None

    def test_fuzzing_request(self):
        if hasattr(self, 'url'):
            for i in range(self.num_iterations):
                seed = self.choose_next()
                energy = self.assign_energy(seed)
                get_post_probability = 0.5
                for j in range(energy):
                    mutated_seed = self.mutate_input(seed)
                    request_json = copy.deepcopy(mutated_seed)
                    del request_json["count"]
                    try:
                        if random.random() < get_post_probability:
                            output = requests.post(self.url, headers=self.headers, json=request_json)
                        else:
                            output = requests.get(self.url, params=request_json)
                        if self.reveals_bug(mutated_seed, output):
                            self.failureQ.append(mutated_seed)
                        elif self.is_interesting():
                            self.seedQ.append(mutated_seed)
                    except requests.exceptions.RequestException as e:
                        self.failureQ.append(mutated_seed)

            subprocess.run(["coverage", "report", "-m"], check=True)
            subprocess.run(["coverage", "html"], check=True)

            with open("seed.json", "w") as f:
                json.dump(self.seedQ, f)
            with open("failure.json", "w") as f:
                json.dump(self.failureQ, f)
        else:
            print("URL attribute is not defined in the FuzzingTestCase object.")

    def choose_next(self):
        if self.seedQ:
            self.seedQ = [elem if isinstance(elem, dict) else {"count": 0} for elem in self.seedQ]
            self.seedQ = sorted(self.seedQ, key=lambda d: d.get("count", 0))
            return self.seedQ[0]
        else:
            return {"count": 0}

    def assign_energy(self, seed):
        return 20
    
    def mutate_input(self, input_data):
        # Define mutation operations
        mutations = ("bitflip", "byteflip", "arith inc/dec", "interesting values", "random bytes", "delete bytes", "insert bytes", "overwrite bytes", "cross over")
        mutation_chose = random.choice(mutations)
        mutated_data = {}
        for key, value in input_data.items():
            if key != "count":
                mutated_data[key] = self.apply_mutation(value, mutation_chose, key)
            if key == "count":
                mutated_data[key] = 0
        return mutated_data

    def apply_mutation(self, data, mutation, key):
        # Apply mutation to data
        mutated_data = data.copy()
        if mutation == "bitflip":
            # Implement bitflip mutation
            byte_index = random.randint(0, len(mutated_data[key]) - 1)
            bit_index = random.randint(0, 7)
            mutated_data[key][byte_index] ^= 1 << bit_index
        elif mutation == "byteflip":
            # Implement byteflip mutation
            byte_index = random.randint(0, len(mutated_data[key]) - 1)
            mutated_data[key][byte_index] ^= 0xFF
        elif mutation == "arith inc/dec":
            # Implement arithmetic increment/decrement mutation
            byte_index = random.randint(0, len(mutated_data[key]) - 1)
            mutated_data[key][byte_index] += random.choice([-1, 1])
        elif mutation == "interesting values":
            # Implement mutation with interesting values
            mutated_data[key] = [0x00, 0x7F, 0xFF]
        elif mutation == "random bytes":
            # Implement mutation with random bytes
            mutated_data[key] = [random.randint(0x00, 0xFF) for _ in range(len(mutated_data[key]))]
        elif mutation == "delete bytes":
            # Implement mutation to delete bytes
            byte_index = random.randint(0, len(mutated_data[key]) - 1)
            del mutated_data[key][byte_index]
        elif mutation == "insert bytes":
            # Implement mutation to insert bytes
            byte_index = random.randint(0, len(mutated_data[key]))
            mutated_data[key].insert(byte_index, random.randint(0x00, 0xFF))
        elif mutation == "overwrite bytes":
            # Implement mutation to overwrite bytes
            byte_index = random.randint(0, len(mutated_data[key]) - 1)
            mutated_data[key][byte_index] = random.randint(0x00, 0xFF)
        elif mutation == "cross over":
            # Implement mutation with crossover
            byte_index = random.randint(0, len(mutated_data[key]) - 1)
            crossover_index = random.randint(0, len(mutated_data[key][byte_index]) - 1)
            mutated_data[key][byte_index] ^= (1 << crossover_index)
        mutated_data["count"] += 1
        return mutated_data

    def reveals_bug(self, seed, output):
        # Check if the request reveals a bug
        return output.status_code == 500  # Assuming a 500 status code indicates a bug

    def is_interesting(self):
        if self.coverage_before is None:
            # Need to obtain the first coverage data to start comparing
            self.coverage_before = subprocess.run(["coverage", "report", "-m"], check=True, capture_output=True).stdout.decode()
            return True

        # Get the new coverage data
        coverage_after  = subprocess.run(["coverage", "report", "-m"], check=True, capture_output=True).stdout.decode()
        # Check if coverage has increased
        if self.coverage_before != coverage_after:
            return True
        return False


class TargetEventsListener(Device.Listener):
    def __init__(self):
        super().__init__()
        self.got_advertisement = False
        self.advertisement = None
        self.connection = None
        self.fuzz_test_case = FuzzingTestCase()

    def on_advertisement(self, advertisement):
        print(f'{color("Advertisement", "cyan")} <-- {color(advertisement.address, "yellow")}')
        self.advertisement = advertisement
        self.got_advertisement = True

    @AsyncRunner.run_in_task()
    async def on_connection(self, connection):
        print(color(f'[OK] Connected!', 'green'))
        self.connection = connection

        print('=== Discovering services')
        target = Peer(connection)
        attributes = []
        await target.discover_services()
        for service in target.services:
            attributes.append(service)
            await service.discover_characteristics()
            for characteristic in service.characteristics:
                attributes.append(characteristic)
                await characteristic.discover_descriptors()
                for descriptor in characteristic.descriptors:
                    attributes.append(descriptor)

        print(color('[OK] Services discovered', 'green'))
        show_services(target.services)

        print('=== Read/Write Attributes (Handles)')
        for attribute in attributes:
            try:
                await write_target(target, attribute, [0x01])
                await read_target(target, attribute)
            except ProtocolError as error:
                print(color(f'[!]  Cannot operate on attribute 0x{attribute.handle:04X}:', 'yellow'), error)
            except TimeoutError:
                print(color('[X] Operation Timeout', 'red'))

        print('---------------------------------------------------------------')
        print(color('[OK] Communication Finished', 'green'))
        print('---------------------------------------------------------------')

        self.fuzz_test_case.test_fuzzing_request()


async def write_target(target, attribute, bytes):
    try:
        bytes_to_write = bytearray(bytes)
        await target.write_value(attribute, bytes_to_write, True)
        print(color(f'[OK] WRITE Handle 0x{attribute.handle:04X} --> Bytes={len(bytes_to_write):02d}, Val={hexlify(bytes_to_write).decode()}', 'green'))
        return True
    except ProtocolError as error:
        raise error
    except TimeoutError:
        raise TimeoutError('Write Timeout')


async def read_target(target, attribute):
    try: 
        read = await target.read_value(attribute)
        value = read.decode('latin-1')
        print(color(f'[OK] READ  Handle 0x{attribute.handle:04X} <-- Bytes={len(read):02d}, Val={read.hex()}', 'cyan'))
        return value
    except ProtocolError as error:
        raise error
    except TimeoutError:
        raise TimeoutError('Read Timeout')


async def main():
    if len(sys.argv) != 2:
        print('Usage: run_controller.py <transport-address>')
        print('example: ./run_ble_tester.py tcp-server:0.0.0.0:9000')
        return

    while True:
        print('>>> Waiting connection to HCI...')
        async with await open_transport_or_link(sys.argv[1]) as (hci_source, hci_sink):
            print('>>> Connected')

            link = LocalLink()
            zephyr_controller = Controller('Zephyr', host_source=hci_source,
                                           host_sink=hci_sink,
                                           link=link)

            device = Device.from_config_file('tester_config.json')
            device.host = Host()
            device.host.controller = Controller('Fuzzer', link=link)
            device.listener = TargetEventsListener()

            await device.power_on()
            await device.start_scanning()

            print('Waiting Advertisement from BLE Target')
            while not device.listener.got_advertisement:
                await asyncio.sleep(0.5)
            await device.stop_scanning()

            print(color('\n[OK] Got Advertisement from BLE Target!', 'green'))
            target_address = device.listener.advertisement.address

            print(f'=== Connecting to {target_address}...')
            await device.connect(target_address)

            await hci_source.wait_for_termination()

        await asyncio.sleep(1)  

logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
asyncio.run(main())


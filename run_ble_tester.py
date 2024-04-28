import logging
import asyncio
import signal
import string
import sys
import os
import subprocess
import json
import random
import copy
import unicodedata
from threading import Thread
from binascii import hexlify
import coverage

from bumble.device import Device, Peer
from bumble.host import Host
from bumble.gatt import show_services
from bumble.core import ProtocolError
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.transport import open_transport_or_link
from bumble.utils import AsyncRunner
from bumble.colors import color

pheromone_decrease = -1
pheromone_increase = 10
p = None
cov = coverage.Coverage(source=".")
cov.start()

def start_target():
    global p
    command = ["./zephyr.exe", "--bt-dev=127.0.0.1:9000"]
    try:
        with open("server_output.txt", "w") as out_file, open("server_error.txt", "w") as error_file:
            p=subprocess.Popen(command,
                               stdout=out_file,
                               stderr=error_file)
        print("Zephyr started")
    except Exception as e:
        print("Error starting Zephyr", str(e))
        return None

class TargetEventsListener(Device.Listener):
    def __init__(self):
        super().__init__()
        self.got_advertisement = False
        self.advertisement = None
        self.connection = None
        self.coverage_before = None
        self.seed_queue = []

    def on_advertisement(self, advertisement):
        print(f'{color("Advertisement", "cyan")} <-- {color(advertisement.address, "yellow")}')
        self.advertisement = advertisement
        self.got_advertisement = True

    @AsyncRunner.run_in_task()
    async def on_connection(self, connection):
        global pheromone_decrease, pheromone_increase, p
        print(color(f'[OK] Connected!', 'green'))
        self.connection = connection

        print('=== Discovering services')
        target = Peer(connection)
        attributes = []
        await target.discover_services()
        for service in target.services:
            await service.discover_characteristics()
            for characteristic in service.characteristics:
                # only take note of the writeable attributes, as non-writeable attributes wouldn't be taking in inputs anyways
                if "WRITE" in str(characteristic):
                    attributes.append(characteristic)

        print(color('[OK] Services discovered', 'green'))
        show_services(target.services)
        signal.signal(signal.SIGINT, self.signal_handler)
        print('=== Fuzzer start')
        with open('seed.json', 'r') as f:
            self.seed_queue = json.load(f)
        # start fuzzing loop
        while True:
            # choose seed based on lowest count value
            seed = self.choose_next()
            print(seed)
            # assign energy based on seed's pheromone value
            energy = self.assign_energy(seed)
            for _ in range(energy):
                data = seed
                # mutate data
                mutated_data = self.mutate_input(data)
                data_to_send = mutated_data["payload"]
                # send request
                for attribute in attributes:
                    try:
                        await write_target(target, attribute, bytes(data_to_send, "ascii"))
                        await read_target(target, attribute)
                    except ProtocolError as error:
                        print(color(f'[!]  Cannot operate on attribute 0x{attribute.handle:04X}:', 'yellow'), error)
                    except TimeoutError:
                        print(color('[X] Operation Timeout', 'red'))
                        p.kill()
                        print("Zephyr crashed, restarting...")
                        start_target()
                        continue
                cov.stop()
                cov.save()
                if self.is_interesting():
                    self.seed_queue.append(mutated_data)
                    self.seed_queue[0]["pheromone"] += pheromone_increase
                cov.start()

        print('---------------------------------------------------------------')
        print(color('[OK] Communication Finished', 'green'))
        print('---------------------------------------------------------------')
        
    def choose_next(self):
        if len(self.seed_queue) != 0:
            self.seed_queue.sort(key=lambda x: x["count"])
            self.seed_queue[0]["count"] += 1
            if self.seed_queue[0]["pheromone"] > 0:
                self.seed_queue[0]["pheromone"] += pheromone_decrease
            print(self.seed_queue[0]["pheromone"])
            return self.seed_queue[0]
        return "Seed queue is empty"

    def assign_energy(self, seed):
        # ant colony optimisation
        return seed["pheromone"] + 1
    
    def mutate_input(self, input_data):
        # Define mutation operations
        mutations = ("bitflip", "byteflip", "arith inc/dec", "interesting values", "random bytes", "delete bytes", "insert bytes", "overwrite bytes", "cross over")
        mutation_chose = random.choice(mutations)
        mutated_data = {}
        for key, value in input_data.items():
            if key == "count":
                mutated_data[key] = 0
            elif key == "pheromone":
                mutated_data[key] = 10
            else:
                mutated_data[key] = self.apply_mutation(value, mutation_chose, key)
            
        return mutated_data

    def apply_mutation(self, data, mutation, key):
        if data == "" or data is None:
            data = ''.join(random.choice(string.printable) for i in range(random.randint(1,50)))
        # Apply mutation to data
        mutated_data = bytearray()
        mutated_data.extend(data.encode("ascii"))
        if mutation == "bitflip":
            n = random.choice((1,2,4))
            for i in range(0, len(mutated_data)*8, 1):
                byte_index = i // 8
                bit_index = i % 8
                for _ in range(n):
                    if i < len(mutated_data)*8:
                        mutated_data[byte_index] ^= (1 << (bit_index))
        elif mutation == "byteflip":
            n = random.choice((1,2,4))
            for i in range(0, len(mutated_data), 1):
                for j in range(n):
                    if (i+j) < len(mutated_data):
                        mutated_data[i+j] ^= 0xFF
        elif mutation == "arith inc/dec":
            n = random.choice((1,2,4))
            operator = random.choice((1, -1))
            for i in range(0, len(mutated_data), 1):
                for j in range(n):
                    if (i+j) < len(mutated_data):
                        mutated_data[i+j] = (mutated_data[i+j] + operator) % 256
        elif mutation == "interesting values":
            interesting_values = (0x00, 0xFF, 0x7F, 0x80, 0x01, 0x7E, 0x7D, 0x7C, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
            n = random.choice((1,2,4))
            for i in range(0, len(mutated_data), 1):
                for j in range(n):
                    if (i+j) < len(mutated_data):
                        mutated_data[i+j] = random.choice(interesting_values)
        elif mutation == "random bytes":
            byte_index = random.randint(0, len(mutated_data)-1)
            mutated_data[byte_index] = random.randint(0, 255)
        elif mutation == "delete bytes":
            size = random.randint(1, 4)
            start = random.randint(0, len(mutated_data))
            del mutated_data[start:start+size]
        elif mutation == "insert bytes":
            size = random.randint(1, 4)
            start = random.randint(0, len(mutated_data))
            mutated_data[start:start] = bytearray(random.sample(range(256), k=size))
        elif mutation == "overwrite bytes":
            size = random.randint(1, 4)
            start = random.randint(0, len(mutated_data))
            mutated_data[start:start+size] = bytearray(random.sample(range(256), k=size))
        elif mutation == "cross over":
            data2 = random.choice(self.seed_queue)
            other_data = bytearray()
            other_data.extend(data2[key].encode("ascii"))
            if len(other_data) < len(mutated_data):
                splice_loc = random.randint(0, len(other_data))
            else:
                splice_loc = random.randint(0, len(mutated_data))
            mutated_data[splice_loc:] = other_data[splice_loc:]
        mutated_data = unicodedata.normalize("NFKD", bytes(mutated_data).decode("ascii", errors="ignore"))
        if mutated_data == "" or mutated_data is None:
            mutated_data = ''.join(random.choice(string.printable) for i in range(random.randint(1,50))) 
        print("data:", mutated_data)
        return mutated_data

    def is_interesting(self):
        # Get the coverage data before
        if self.coverage_before is None:
            self.coverage_before = cov.json_report(pretty_print=True)
            return True

        # Get the new coverage data
        coverage_after = cov.json_report(pretty_print=True)
        # Check if coverage has increased
        if self.coverage_before != coverage_after:
            self.coverage_before = coverage_after
            return True
        return False
    
    def signal_handler(self, sig, frame):
        cov.stop()
        cov.save()
        print(cov.report())
        print("Exiting...")
        
        exit(0)   


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
    global p
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

            start_target()

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


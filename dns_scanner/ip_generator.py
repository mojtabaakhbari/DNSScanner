"""
IP generation strategies for DNS Scanner.

Author: Mojtaba Akhbari
"""

import random
import ipaddress
from .config import LEAKED_SUBNETS, CUSTOM_FIRST_OCTETS, CUSTOM_FIRST_AND_SECOND_OCTETS


def get_heuristic_host_octet():
    roll = random.random()
    if roll < 0.25:
        return random.choice([1, 2, 5, 8, 9, 10, 53, 100, 253, 254])
    elif roll < 0.50:
        return random.randint(3, 30)
    elif roll < 0.60:
        return random.choice([64, 65, 128, 129, 192, 193])
    else:
        return random.randint(31, 252)


def get_heuristic_mid_octet():
    roll = random.random()
    if roll < 0.20:
        return random.choice([0, 8, 16, 32, 64, 128, 192, 224])
    elif roll < 0.35:
        return random.randint(1, 20)
    elif roll < 0.50:
        return random.choice([253, 254, 255])
    else:
        return random.randint(0, 255)


def is_public(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return ip.is_global and not ip.is_multicast and not ip.is_unspecified
    except:
        return False


def generate_random_public_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, (2**32) - 1))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def generate_custom_octet_ip():
    first = random.choice(CUSTOM_FIRST_OCTETS)
    second = get_heuristic_mid_octet()
    third = get_heuristic_mid_octet()
    fourth = get_heuristic_host_octet()
    return f"{first}.{second}.{third}.{fourth}"


def generate_lite_custom_ip():
    prefix = random.choice(CUSTOM_FIRST_AND_SECOND_OCTETS)
    third = get_heuristic_mid_octet()
    fourth = get_heuristic_host_octet()
    return f"{prefix}.{third}.{fourth}"


def get_networks_from_file(filename, nearby):
    networks = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                if "/" in line:
                    networks.append(ipaddress.IPv4Network(line, strict=False))
                else:
                    ip = ipaddress.IPv4Address(line)
                    if nearby:
                        net = ipaddress.IPv4Network(f"{line}/24", strict=False)
                        networks.append(net)
                    else:
                        networks.append(
                            ipaddress.IPv4Network(f"{line}/32", strict=False)
                        )
            except ValueError:
                pass
    return networks


class IPGenerator:
    def __init__(self):
        self.leaked_networks = [
            ipaddress.IPv4Network(n, strict=False) for n in LEAKED_SUBNETS
        ]

    async def generate_ips(self, args, queue, stop_event):
        async def safe_put(item):
            while not stop_event.is_set():
                try:
                    import asyncio

                    await asyncio.wait_for(queue.put(item), timeout=0.5)
                    return True
                except asyncio.TimeoutError:
                    continue
            return False

        try:
            if args.random:
                for _ in range(args.random):
                    if not await safe_put(generate_random_public_ip()):
                        break

            elif args.cf:
                for _ in range(args.cf):
                    if not await safe_put(generate_custom_octet_ip()):
                        break

            elif args.cl:
                for _ in range(args.cl):
                    if not await safe_put(generate_lite_custom_ip()):
                        break

            elif args.al or args.ls:
                if args.ls:
                    for _ in range(args.ls):
                        net = random.choice(self.leaked_networks)
                        ip = ipaddress.IPv4Address(
                            random.randint(
                                int(net.network_address), int(net.broadcast_address)
                            )
                        )
                        if not await safe_put(str(ip)):
                            break
                else:
                    for net in self.leaked_networks:
                        for ip in net:
                            if not await safe_put(str(ip)):
                                break

            elif args.file:
                networks = get_networks_from_file(args.file, args.nearby)
                for net in networks:
                    for ip in net:
                        if not await safe_put(str(ip)):
                            break

        except Exception as e:
            pass
        finally:
            for _ in range(args.concurrency):
                if not await safe_put(None):
                    break

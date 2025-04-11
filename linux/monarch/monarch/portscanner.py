import asyncio
import ipaddress
from collections import defaultdict
from .config_manager import SHORT_TIMEOUT
from .monarch_logger import setup_logger

logger = setup_logger("Port Scanner")


class ServerAddress:
    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = port

    def get_socket_address(self):
        return (self.ip_address, self.port)


async def scan_address(server_address):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(*server_address.get_socket_address()),
            timeout=SHORT_TIMEOUT,
        )
        writer.close()
        return server_address
    except Exception:
        return None


async def parse_port_string(port_string):
    port_ranges = port_string.split(",")

    port_list = []
    for port_range in port_ranges:
        port_range = port_range.strip()
        if "-" in port_range:
            bounds = port_range.split("-")
            port_list.extend(
                [port_num for port_num in range(int(bounds[0]), int(bounds[1]) + 1)]
            )
        else:
            port_list.append(int(port_range))

    return port_list


async def generate_server_addresses(subnets, port_list):
    server_address_list = []

    ip_addresses = []
    for subnet in subnets:
        ip_addresses.extend([str(ip) for ip in ipaddress.IPv4Network(subnet)])

    for ip_address in ip_addresses:
        server_address_list.extend(
            [ServerAddress(ip_address, port) for port in port_list]
        )

    return server_address_list


async def generate_dict(server_address_list):
    """make a dictionary with the ip as key, and the list of ports open as value"""
    host_dict = defaultdict(list)
    for server_address in server_address_list:
        if server_address:
            host_dict[server_address.ip_address].append(server_address.port)
    return host_dict


async def scan_network(
    subnets,
    ports="22,3389,88,135,389,445,5985,3306,5432,27017,53,80,443,8080",
):
    for subnet in subnets:
        logger.info(f"nmap --min-rate 3000 -p {ports} --open {subnet}")
        logger.info(
            f"rustscan -a {subnet} -g -t {int(SHORT_TIMEOUT * 1000)} -p {ports}"
        )
    port_list = await parse_port_string(ports)

    server_address_list = await generate_server_addresses(subnets, port_list)
    tasks = [scan_address(server_address) for server_address in server_address_list]
    results = await asyncio.gather(*tasks)

    host_dict = await generate_dict(results)

    return host_dict


if __name__ == "__main__":
    a = asyncio.run(scan_network(["10.100.40.0/24"], "22,80"))
    print(a)



import subprocess
import pathlib
import platform


def scan_binary_for_os() -> pathlib.Path:
    suffixes = {
        'Windows': 'windows.exe',
        'Linux': 'linux',
        'Darwin': 'macos',
    }
    sys = platform.system()
    suffix = suffixes.get(sys)
    if suffix is None:
        raise NotImplementedError(f'Platform not supported: {sys}')
    return pathlib.Path(f'./scanning/rustscan-{suffix}')

RUSTSCAN_PATH=scan_binary_for_os()


def run_scan(subnet: str, ports: list[int]) -> str:
    '''
    Takes in subnet in the form "172.16.100.0/24"
    runs a fast scan on given ports and returns the output as a list of found ip addresses
    '''
    
    port_string = ','.join(str(port) for port in ports)


    args = [RUSTSCAN_PATH, '-a', subnet, '-p', port_string, '-g']


    popen = subprocess.run(
        args = args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    output = popen.stdout.decode("utf-8")

    return clean_output(output)

def clean_output(output: str):
    '''removes any ip addresses that end in .1 or .2, and splits the giant string output to become an array'''
    hosts = []

    lines = output.splitlines()

    for line in lines:
        host = line.split()[0]
        last_octet = line.split('.')[-1]
        if last_octet != '.1' and last_octet != '.2' and len(host) > 0:
            hosts.append(host)



    return [ host for host in hosts if host[-2:] != '.1' and host[-2:] != '.2' and len(host) > 0]



def scan_subnets(subnets: list[str], ports: list[int]): 
    #returns a list of list, because then it is easier to map the password to it in dominion utils
    hosts = []
    for subnet in subnets:
        hosts.append(run_scan(subnet, ports))
    return hosts





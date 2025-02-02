#!/usr/bin/env python

import dominion
import scanning
import printer
import time
import subprocess
import sys
import json
import prettytable
from typing import Callable
import paramiko


class Host:
    def __init__(self, ip: str, user: str, password: str, port: int, aliases: list[str]=None) -> None:
        if aliases is None:
            aliases = []
        self.ip = ip
        self.user = user
        self.password = password
        self.port = port
        self.aliases = aliases

    def __repr__(self):
        cls = type(self).__name__
        return f'{cls}(ip={self.ip!r}, user={self.user!r}, password={self.password!r}, port={self.port!r}, aliases={self.aliases!r})'

    def __eq__(self, other):
        if not isinstance(other, Host):
            return NotImplemented
        return (self.ip, self.user, self.password, self.port, self.aliases) == (other.ip, other.user, other.password, other.port, other.aliases)

    @staticmethod
    def parse(line: str) -> [str, 'Host']:
        ip, user, password, port, *aliases = line.split()
        host = Host(ip, user, password, int(port), aliases)
        return host

    def __str__(self) -> str:
        if len(self.aliases) == 0:
            aliases = ''
        else:
            aliases = ' ' + ' '.join(self.aliases)
        return f'{self.ip} {self.user} {self.password} {self.port}{aliases}'
    
    def name(self) -> str:
        if self.aliases:
            return self.aliases[0]
        else :
            return self.ip


class RunResult:
    def __init__(self, ip: str, obj: dict):
        # TODO: This is annoying because I need to keep this up to date with coordinate
        # Maybe this is fine because coordinate shouldn't change much?
        self.stdout = obj['stdout']
        self.stderr = obj['stderr']
        self.login_ok = obj['login_ok']

class RunHost:
    def __init__(self, host: Host, env: list[str]):
        self.user = host.user
        self.password = host.password
        self.port = host.port
        self.env = env

def clean_log() -> None:
    with open(dominion.LOG_FILE, 'w') as file:
        file.write('')
    file.close()

def die(type: str) -> None:
    if type == dominion.ERROR:
        printer.message("Exiting...", dominion.ERROR)
        raise SystemExit(1)
    else:
        printer.message("Exiting...", dominion.SUCCESS)
        raise SystemExit(0)

def log(string: str) -> None:
    current_time = time.localtime()

    with open(dominion.LOG_FILE, 'a') as file:
        file.write(f'[LOG-{time.strftime("%H:%M:%S", current_time)}] {string}' + '\n')
    file.close()

# Runs scripts against multiple hosts, shared between run_script and run_script_against_all_hosts
def run_script_impl(input: dict[str, RunHost], script: str) -> dict[str, RunResult]:
    json_str = json.dumps(input)
    args = [dominion.BINARY, '-j', json_str, '-T', '15', '-R', '-S', '-y', script]
    proc = subprocess.run(args, capture_output=True)

    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)


    with open('output.json') as output:
        obj = json.load(output)
        results = {ip: RunResult(ip, values) for ip, values in obj.items()}
        return results

def run_script(host: Host, script: str, env_vars=None) -> RunResult:
    env = [] if env_vars is None else env_vars.split(',')
    results = run_script_impl({host.ip: RunHost(host, env).__dict__}, script)
    return results[host.ip]

def run_script_multi(hosts: dict[str, Host], script: str, make_env: Callable[Host, list[str]] = lambda h: []) -> dict[str, RunResult]:
    hosts = {host.ip: RunHost(host, make_env(host)).__dict__ for _, host in hosts.items()}
    return run_script_impl(hosts, script)

def run_script_against_all_hosts(script: str, make_env: Callable[Host, list[str]] = lambda h: []) -> dict[str, RunResult]:
    return run_script_multi(read_all(), script, make_env)

def run_script_against_all_hosts_with_env_vars(script: str, env_vars):
    for ip, host in read_all().items():
        run_script(host, script, env_vars)

def read_all() -> dict[str, Host]:
    data = {}
    with open(dominion.IP_USER_MAP, 'r') as file:
        for line in file:
            if line.strip().startswith('#'):
                continue

            host = Host.parse(line)
            data[host.ip] = host
    return data

def map_args_to_env_vars(args: list) -> str:
    alphabet = [x for x in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    env_vars = ""
    for n, arg in enumerate(args): env_vars += f"{alphabet[n]*3}={arg},"
    return env_vars[:-1]

def is_host_in_config(ip: str) -> bool:
    data = read_all()
    if ip in data:
        return True
    else:
        return False

def yes_or_no(question: str) -> bool:
    while True:
        reply = str(input(question+' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            return False

def interactive_add_host(host: Host) -> Host:
    if host.ip == None: ip = input("Enter host IP: ")
    if host.user == None: user = input("Enter username: ")
    if host.password == None: host.password = input("Enter password: ")
    if host.port == None: host.port = input("Enter port: ")
    add_host(host)
    return host

def add_host(host: Host) -> None:
    data = read_all()
    old = data.get(host.ip)
    if old is not None:
        printer.message(f"Host at {host.ip} already exists: {old}, overwriting", dominion.WARNING)
    data[host.ip] = host
    # TODO: Inefficient-ish
    with open(dominion.IP_USER_MAP, 'w') as file:
        file.write("# dominion.conf\n")
        file.write("# [IP ADDRESS] [USERNAME] [PASSWORD] [PORT] [ALIASES...]\n")
        for ip, host in data.items():
            file.write(f"{str(host)}\n")

def scan_networks(subnets: list[str], passwords: list[str]) -> None:
    while(len(passwords) < len(subnets)):
        passwords.append(passwords[0]) #if all subnets use same password, only need to type it in once, so duplicate it in the list
    
    hosts = scanning.scan_subnets(subnets=subnets, ports = [22])
    for subnet_num in range(len(hosts)):
        for ip in hosts[subnet_num]:
            host = Host(ip, 'root', passwords[subnet_num], 22)
            add_host(host)


def execute(exec_string: str) -> None:
    script, hosts, env_vars = None, None, None
    script = exec_string.split(':')[0]
    ips = exec_string.split(':')[1].split(',')
    if len(exec_string.split(':')) == 3:
        env_vars = exec_string.split(':')[2].split(',')

    for ip in ips:
        data = read_all()
        if is_host_in_config(ip):
            host = data[ip]
            if env_vars:
                printer.message(f"Executing '{script}' on {ip} with ({map_args_to_env_vars(env_vars)}) using {host.user}/{host.password} | port: {host.port}")
                run_script(host, script, map_args_to_env_vars(env_vars))
            else:
                printer.message(f"Executing '{script}' on {ip} using {host.user}/{host.password} | port: {host.port}")
                run_script(host, script)
        else:
            printer.message(f"Host {ip} not found in {dominion.IP_USER_MAP}", dominion.ERROR)
            if yes_or_no(f"Add {ip} to {dominion.IP_USER_MAP}?"):
                host = interactive_add_host(host)
                if env_vars:
                    printer.message(f"Executing '{script}' on {ip} with ({map_args_to_env_vars(env_vars)}) using {host.user}/{host.password} | port: {host.port}")
                    run_script(host, script, map_args_to_env_vars(env_vars))
                else:
                    printer.message(f"Executing '{script}' on {ip} using {host.user}/{host.password} | port: {host.port}")
                    run_script(host, script)
            else: 
                continue


def load_status_json():
    """Load status.json data."""
    with open(dominion.STATUS_FILE, 'r') as file:
        return json.load(file)

def display_table():
    with open(dominion.IP_USER_MAP, 'r') as file:
        lines = file.readlines()
    
    # Parse IPs and optional hostnames/aliases
    ip_to_hostname = {}
    for line in lines:
        if line.strip() and not line.strip().startswith('#'):
            parts = line.split()
            ip = parts[0]
            hostname = parts[4] if len(parts) > 4 else None  # Hostname exists only if there are 5 parts
            ip_to_hostname[ip] = hostname
    
    status_data = load_status_json()
    scripts = [script["name"] for script in status_data["scripts"]]
    
    # Initialize the table
    table = prettytable.PrettyTable()
    table.field_names = ["IP"] + scripts

    # Build table rows
    for ip, hostname in ip_to_hostname.items():
        # Display IP with hostname if it exists
        display_ip = f"{ip} ({hostname})" if hostname else ip
        row = [display_ip]
        for script in scripts:
            executed_on = next((s["executed_on"] for s in status_data["scripts"] if s["name"] == script), [])
            if ip in executed_on:
                row.append(f"{printer.bcolors.OKGREEN}✔{printer.bcolors.ENDC}")  # Green checkmark
            else:
                row.append(f"{printer.bcolors.FAIL}x{printer.bcolors.ENDC}")  # Red "x")
        table.add_row(row)

    # Print the table
    print(table)

def update_status(script_name, ip_address):
    with open(dominion.STATUS_FILE, 'r') as file:
        status_data = json.load(file)
    
    script_block = next((script for script in status_data["scripts"] if script["name"] == script_name), None)
    
    if script_block:
        if ip_address in script_block["executed_on"]:
            printer.message(f"IP {ip_address} already exists for script {script_name}. Doing nothing...", dominion.WARNING)
        else:
            script_block["executed_on"].append(ip_address)
            printer.message(f"IP {ip_address} added to script {script_name}.", dominion.SUCCESS)
    else:
        new_script = {
            "name": script_name,
            "executed_on": [ip_address]
        }
        status_data["scripts"].append(new_script)
        printer.message(f"New script block {script_name} created with IP {ip_address}.", dominion.SUCCESS)
    
    with open(dominion.STATUS_FILE, 'w') as file:
        json.dump(status_data, file, indent=4)


def upload_file(host: Host, local_path: str, remote_path: str):

    ssh = get_ssh_client(host)
    try:
        with ssh.open_sftp() as sftp:
            sftp.put(local_path, remote_path)
        
        printer.message(f'{local_path} succesfully uploaded to {host.name()} at {remote_path}', dominion.SUCCESS)
    except Exception as e:
        printer.message(f'Error uploading file to {host.name()}: {e}', dominion.ERROR)
    finally:
        ssh.close()



def upload_to_ips(local_path, remote_path, ips=None):
    data = read_all()

    if not ips:
        ips = data.keys()

    for ip in ips:
        if is_host_in_config(ip):
            host = data[ip]
            upload_file(host, local_path, remote_path)

        else:
            printer.message(f"Host {ip} not found in {dominion.IP_USER_MAP}", dominion.ERROR)
    




def get_ssh_client(host: Host):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host.ip, username=host.user, password=host.password)
    return ssh

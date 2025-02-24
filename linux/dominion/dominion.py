#!/usr/bin/env python
import domlogging
import passwords
import argparse
import pathlib
import printer
import utils
import base
import os
import platform

def binary_for_os() -> pathlib.Path:
    suffixes = {
        'Windows': 'windows.exe',
        'Linux': 'linux',
        'Darwin': 'macos',
    }
    sys = platform.system()
    suffix = suffixes.get(sys)
    if suffix is None:
        raise NotImplementedError(f'Platform not supported: {sys}')
    return pathlib.Path(f'../coordinate/coordinate-{suffix}')

IP_USER_MAP = pathlib.Path("conf/dominion.conf")
PASSWORDS_DB = pathlib.Path("conf/passwords.db")
STATUS_FILE = pathlib.Path("conf/status.json")
LOG_FILE = pathlib.Path("log/dominion.log")
BINARY = binary_for_os()
WARNING = "WARNING"
SUCCESS = "SUCCESS"
ERROR = "ERROR"

def main() -> None:
    parser = argparse.ArgumentParser(description='Dominion. A python wrapper for "coordinate" to more effectively manage multiple Linux hosts.')

    parser.add_argument('-R', '--rotate', help=f'Change all passwords in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-D', '--display', help=f'display current status', action='store_true')
    parser.add_argument('-I', '--inventory', help=f'Run Inventory on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-B', '--basic', help=f'Run "basic" inventory on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-BLUE', '--blue', help=f'"blue.sh" on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-LOG', '--logging', help=f'Run logging.sh on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-SSH', '--ssh', help=f'SSH hardening on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-PHP', '--php', help=f'PHP hardening on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-POL', '--pwpolicy', help=f'Password policy capture on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-PII', '--pii', help=f'PII scan on all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-N', '--normalize', help=f'normalize.sh all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-IB', '--initialbase' , help=f'initial_base.sh all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-PASSES', '--passwords', help=f'pass.sh for all hosts in {IP_USER_MAP}', action='store_true')
    parser.add_argument('-H', '--hosts', help=f'Generate an /etc/hosts file for all hosts in {IP_USER_MAP}', action='store_true')

    parser.add_argument('-IDENT', '--ident', help=f'Run ident.sh on all boxes', action='store_true')
    parser.add_argument('-LOCK', '--lockdown', help=f'Run lockdown.sh on all boxes', action='store_true')

    parser.add_argument('-S', '--scan', help=f'scan all hosts in provided subnets: -S=10.200.1.0/24,10.200.2.0/24:password', type=str)
    parser.add_argument('-F', '--firewall', help=f'run basic firewall', action='store_true')
    
    parser.add_argument('-E', '--execute', help=f'Execute script on provided hosts: -E=/path/to/script.sh:192.168.220.12,192.168.220.13:arg1,arg2,arg3', type=str)
    parser.add_argument('-EA', '--execute-all', help=f'Execute script on all hosts: -E=/path/to/script.sh:arg1,arg2,arg3', type=str)

    parser.add_argument('-U', '--upload', help=f'upload file from local to remote host: -U=/local/path:/remote/path:192.168.220.12,192.168.220.13')
    parser.add_argument('-UA', '--upload-all', help=f'upload file from local on all remote hosts: -UA=/local/path:/remote/path')
    parser.add_argument('-UF', '--upload-firewall', help='upload firewall template on all moachines', action='store_true')    
    
    parser.add_argument('-DOWN', '--download', help=f'download file from remote host: -DOWN=/local/dir:/remote/path:192.168.220.12,192.168.220.13')
    parser.add_argument('-DA', '--download-all', help=f'download file from all remote hosts: -DA=/local/dir:/remote/path')


    parser.add_argument('-A', '--add', help=f'Add host to {IP_USER_MAP}: -A=192.168.220.12:root:password', type=str)
    parser.add_argument('-C', '--clear', help=f'Clear log file at {LOG_FILE}', action='store_true')

    parser.add_argument('-BAN', '--banip', help='Blocks input and output to the IP specified', action="extend", nargs=1)


    args = parser.parse_args()

    if not os.path.exists(IP_USER_MAP):
        printer.message(f"{IP_USER_MAP} not found.", WARNING)
        utils.die(ERROR)

    if not os.path.exists(PASSWORDS_DB):
        printer.message(f"{PASSWORDS_DB} not found.", WARNING)
        utils.die(ERROR)

    if not os.path.exists(LOG_FILE):
        printer.message(f"{LOG_FILE} not found.", WARNING)
        utils.die(ERROR)

    if args.clear:
        utils.clean_log()

    if args.add:
        ip, username, password = args.add.split(':')[0], args.add.split(':')[1], args.add.split(':')[2]
        utils.add_host(utils.Host(ip, username, password))

    if args.scan:
        arguments = args.scan.split(':')
        passwords_list = arguments[1].split(',')
        subnets = arguments[0].split(',')
        utils.scan_networks(subnets, passwords_list)


    if args.rotate:
        data = utils.read_all()
        passwords.change_all_root_passwords(data)

    if args.inventory:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-inventory/inventory.sh"))

    if args.firewall:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-inventory/dominion_fw.sh"))

    if args.basic:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-inventory/baseq.sh"))

    if args.pii:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-toolbox/pii.sh"))

    if args.pwpolicy:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-toolbox/pw_pol.sh"))

    if args.blue:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-hardening/blue.sh"))

    if args.ssh:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-hardening/ssh.sh"))

    if args.php:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-hardening/php.sh"))

    if args.normalize:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-toolbox/normalize.sh"))

    if args.initialbase:
        base.initial_base_across_boxes()

    if args.logging:
        data = utils.read_all()
        domlogging.logging_across_boxes(data)

    if args.passwords:
        utils.run_script_against_all_hosts(pathlib.Path("../linux-hardening/pass.sh"))

    if args.display:
        utils.display_table()

    if args.execute:
        utils.execute(args.execute)
    
    if args.execute_all:
        arguments = args.execute_all.split(':')
        script_path = arguments[0]

        
        if len(arguments) == 1:
            utils.run_script_against_all_hosts(script_path)
        else:
            env_vars = utils.map_args_to_env_vars( (args.execute_all.split(':')[1]).split(','))
            utils.run_script_against_all_hosts_with_env_vars(script_path, env_vars)
    
    if args.upload:
        arguments = args.upload.split(':')
        local_path = arguments[0]
        remote_path = arguments[1]
        ips = arguments[2].split(',')
        utils.upload_to_ips(local_path, remote_path, ips)
    
    if args.upload_all:
        arguments = args.upload_all.split(':')
        local_path = arguments[0]
        remote_path = arguments[1]
        utils.upload_to_ips(local_path, remote_path)

    if args.upload_firewall:
        firewall_template_local_path='../linux-toolbox/firewall/firewall_template.sh'

        firewall_template_remote_path='/root/firewall_template.sh'

        utils.upload_to_ips(firewall_template_local_path, firewall_template_remote_path)
        

    if args.download:
        arguments = args.upload.split(':')
        local_path = arguments[0]
        remote_path = arguments[1]
        ips = arguments[2].split(',')
        utils.download_from_ips(local_path, remote_path, ips)
    
    if args.download_all:
        arguments = args.upload_all.split(':')
        local_path = arguments[0]
        remote_path = arguments[1]
        utils.download_from_ips(local_path, remote_path)

    if args.banip:
        env_vars = utils.map_args_to_env_vars(args.banip)
        utils.run_script_against_all_hosts_with_env_vars(pathlib.Path("../linux-toolbox/banip.sh"), env_vars)

    if args.ident:
        utils.run_script_against_all_hosts('../linux-inventory/ident.sh')

    if args.lockdown:
        utils.run_script_against_all_hosts('../linux-hardening/lockdown.sh')


    if args.hosts:
        data = utils.read_all()
        results = utils.run_script_against_all_hosts(pathlib.Path("../linux-inventory/hostname.sh"))
        for ip, result in results.items():
            lines = result.stdout.splitlines()
            if not len(lines) == 1:
                printer.message(f'{ip} hostname output invalid, got: {lines}', WARNING)
            else:
                hostname = lines[0]
                printer.message(f'{ip} hostname is {hostname}', SUCCESS)
                host = data[ip]
                host.aliases.append(hostname)
                utils.add_host(host)

if __name__ == "__main__":
    utils.log("Dominion started")
    printer.print_banner()
    main()

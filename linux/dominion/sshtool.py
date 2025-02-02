import argparse
import dominion
import pathlib
import printer
import utils
import os
import sys
import re
import shutil

IP_REGEX = re.compile('^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$')
WARNING = "WARNING"
SUCCESS = "SUCCESS"
ERROR = "ERROR"

def main() -> None:
    parser = argparse.ArgumentParser(description='sshtool: Use dominion''s configuration file to ssh into boxes')
    parser.add_argument('-l', '--list', help='List all boxes available.', action='store_true')
    parser.add_argument('-b', '--box', help='''IP or hostname of box to SSH into (case insensitive).
        If this is a string and there are no exact matches, it will be treated as a prefix, which will only succeed
        if exactly one box contains it as a prefix.''')
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    if shutil.which('sshpass') is None:
        printer.message('Could not find sshpass! Please install it before running this program!', ERROR)
        utils.die(ERROR)

    data = utils.read_all()

    if args.list:
        for ip, host in data.items():
            print(f'{host.user}@{ip}:{host.port} (aka {host.aliases})')

    matches = []

    if args.box:
        ip = None
        if not IP_REGEX.match(args.box):
            for _, host in data.items():
                for alias in host.aliases:
                    if alias.lower() == args.box.lower():
                        ip = host.ip
                        printer.message(f'Found IP {ip} for hostname {args.box}', SUCCESS)
                        break
                    elif alias.lower().startswith(args.box.lower()):
                        matches.append([host.ip, alias])
        else:
            ip = args.box

        if ip is None:
            if len(matches) == 0:
                printer.message(f'Could not find corresponding IP for {args.box}', WARNING)
                utils.die(ERROR)
            elif len(matches) == 1:
                ip, alias = matches[0]
                printer.message(f'Prefix matched host {ip} with alias {alias}', SUCCESS)
            else:
                printer.message(f'Prefix matched multiple hosts: {matches}', WARNING)
                utils.die(ERROR)

        host = data[ip]
        cmdline = ['sshpass', '-p', host.password, 'ssh', '-o', 'StrictHostKeyChecking=no', f'{host.user}@{host.ip}', '-p', str(host.port)]
        printer.message(' '.join(cmdline))
    
        os.execvp(cmdline[0], cmdline)

if __name__ == '__main__':
    main()

#!/usr/bin/env python

import dominion
import random 
import printer
import utils

def change_all_root_passwords(data: dict) -> None:
    failed = []
    data = utils.read_all()

    passwords = {}

    def choose_pass(host: utils.Host) -> list[str]:
        index, password = get_random_password()
        # TODO: This removes passwords that have not been guaranteed to have been used yet!
        # But also just generate more passwords lol
        remove_used_password(password)
        passwords[host.ip] = password
        printer.message(f"Using password {index} ({password}) for host {host.ip}")
        return [f"AAA={host.user}", f"BBB={password}"]

    results = utils.run_script_against_all_hosts("../linux-toolbox/pass_for.sh", choose_pass)
    for ip, result in results.items():
        host = data[ip]

        if not result.login_ok:
            printer.message(f"Failed to log in to {ip} to run script", dominion.ERROR)
            del data[ip]
            failed.append(host)
            continue

        new_pass = passwords[ip]
        host.password = new_pass

    login = utils.run_script_multi(data, "../linux-toolbox/hello.sh")
    for ip, result in login.items():
        host = data[ip]

        if not result.login_ok:
            printer.message(f"Failed to log in to {ip} with new password", dominion.ERROR)
            failed.append(host)
        else:
            printer.message(f"Successfully changed password on {ip}", dominion.SUCCESS)
            utils.update_status("pass_for.sh", ip)
            utils.add_host(host)
    if len(failed) > 0:
        printer.message(f"Failed to change password on {len(failed)} hosts", dominion.ERROR)
        for host in failed:
            printer.message(f"> {host.ip} (a.k.a. '{host.aliases}')", dominion.ERROR)
    else:
        printer.message(f"Successfully Changes passwords on all hosts", dominion.SUCCESS)

def get_random_password() -> str:
    with open(dominion.PASSWORDS_DB, 'r') as file:
        passwords = file.readlines()

    if passwords:
        selected_password = random.choice(passwords)
        return selected_password.split(',')[0].strip(), selected_password.split(',')[1].strip()
    else:
        utils.log("No passwords available in passwords.db")
        raise ValueError("No passwords available in passwords.db")


def remove_used_password(used_password: str) -> None:
    with open(dominion.PASSWORDS_DB, 'r') as file:
        lines = file.readlines()

    with open(dominion.PASSWORDS_DB, 'w') as file:
        for line in lines:
            if line.strip().split(',')[1] == used_password:
                continue
            file.write(line)

def update_password_in_config(ip: str, username: str, password: str, port: int) -> None:
    with open(dominion.IP_USER_MAP, 'r') as file:
        lines = file.readlines()

    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            continue

        parts = line.split()
        if len(parts) == 4 and parts[0] == ip and parts[1] == username and parts[3] == str(port):
            lines[i] = f"{ip} {username} {password} {str(port)}\n"


    with open(dominion.IP_USER_MAP, 'w') as file:
        file.writelines(lines)

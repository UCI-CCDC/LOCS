#!/usr/bin/env python

import random
import csv
from pathlib import Path
from .monarch_logger import setup_logger
from .ssh import (
    execute,
    test_password_works,
    parallel_executor,
    must_get_script,
)
from .config_manager import modify_host
from .utils import maybe_get_host
from threading import Lock
import secrets

logger = setup_logger("Password Manager")


PASSWORDS_DB = Path("passwords.db")


class Password:
    id: str
    password: str


def get_passwords():
    with open(PASSWORDS_DB, "r") as file:
        reader = csv.DictReader(file)
        rows = [row for row in reader]
        if not len(rows) == 0 and "id" not in rows[0]:
            raise ValueError(
                "Invalid format for passwords.db (do you have the headers id and password?)"
            )
        return rows


def write_passwords(passwords):
    with open(PASSWORDS_DB, "w") as file:
        fields = list(Password.__annotations__.keys())
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(passwords)


def choose_pass(ip, passwords, lock):
    with lock:
        if passwords:
            password = random.choice(passwords)
            passwords.remove(password)
            logger.info(
                f"Using password {password['id']} ({password['password']}) for host {ip}"
            )
            return password["password"]
        else:
            logger.error("No passwords available in passwords.db")
            raise ValueError("No passwords available in passwords.db")


def change_password(host, passwords, lock):
    script_path = must_get_script("pass_for.sh")
    new_password = choose_pass(host.ip, passwords, lock)
    result = execute(host, script_path, ["root", new_password])
    if result is not None:
        logger.info(f"Script outputted {result.stdout} on host {host.name()}")
    host.password = new_password
    login_result = test_password_works(host)
    return login_result


def change_root_passwords(alias=None, password=None):
    lock = Lock()
    if password is None:
        passwords = get_passwords()
    elif password.lower().startswith("rand"):
        passwords = [
            {
                "id": str(i),
                "password": secrets.token_urlsafe(12),
            }
            for i in range(100)
        ]
    else:
        passwords = [
            {
                "id": str(i),
                "password": password,
            }
            for i in range(100)
        ]
    hosts = maybe_get_host(alias)
    results = parallel_executor(change_password, hosts, passwords, lock)
    for result in results:
        host = result.host
        if result.successful_login:
            logger.info(f"Successfully changed {host.ip}")
            modify_host(result.host)
        else:
            logger.error(f"Failed in changing {host.ip}")

    if password is None:
        write_passwords(passwords)

from .config_manager import load_config, load_host_list, Host, add_host, modify_host
from .monarch_logger import setup_logger
from .ssh import (
    execute_on_hosts,
    test_password_works,
    get_server_ids,
    must_get_script,
    upload_to_ips,
    download_from_ips,
)
from .portscanner import scan_network
from concurrent.futures import ThreadPoolExecutor
from difflib import get_close_matches
from itertools import product
import asyncio
from urllib.request import urlretrieve
from pathlib import Path

logger = setup_logger("Monarch Utils")


def ip_in_config(ip):
    data = load_config()
    return ip in data


def maybe_get_host(query):
    if query is not None:
        return [get_host(query)]
    else:
        return []


# Throws an exception if a host was not found.
def get_host(query):
    hosts = load_host_list()
    # Get by IP or alias
    for host in hosts:
        if host.ip == query or query in host.aliases:
            return host

    all_aliases = {alias: host for host in hosts for alias in host.aliases}

    # Try to find the best match using difflib
    matches = get_close_matches(
        query, all_aliases.keys(), n=1, cutoff=0.6
    )  # Adjust cutoff if needed
    if matches:
        return all_aliases[matches[0]]  # Return the host with the best-matching alias

    # Get by IP suffix
    if query.startswith("."):
        ips = [host for host in hosts if host.ip.endswith(query)]
        if len(ips) == 1:
            return ips[0]

    raise ValueError(f"No host for alias {query}")  # No match found


def get_valid_host(host, password):
    new_host = Host(ip=host.ip, password=password)
    result = test_password_works(new_host)
    if result.successful_login:
        logger.info(f"{password} worked on {new_host.ip}")
        return new_host

    return None


def initialize_hosts(subnets, password_list):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server_address_dict = loop.run_until_complete(scan_network(subnets, "22"))
    loop.close()
    hosts = [
        Host(ip=ip, open_ports=open_ports)
        for ip, open_ports in server_address_dict.items()
    ]
    for host in hosts:
        logger.info(f"Found host {host.name()} with open SSH port")
    # now, test each host with every password to see if any of them work
    if len(password_list) == 1:
        for host in hosts:
            host.password = password_list[0]
            add_host(host)
    else:
        hosts, password_list = zip(*product(hosts, password_list))  # pyright: ignore
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(get_valid_host, hosts, password_list))
        # add every host to the file
        logger.debug(results)
        for result in results:
            if result is not None:
                add_host(result)


def run_script_across_hosts(script_path, args=[], hosts=[]):
    run_results = execute_on_hosts(script_path, args, hosts)
    for run_result in run_results:
        logger.info(
            f"Ran {script_path} on {run_result.host.name()}: {run_result.stdout}"
        )
        if len(run_result.stderr) > 0:
            logger.error(
                f"Ran {script_path} on {run_result.host.name()}: {run_result.stderr}"
            )
    return run_results


def run_initial_base(host=None):
    hosts = maybe_get_host(host)
    ## need to run php.sh, ssh.sh, upload firewall_template.sh, run initial_back.sh, and ident.sh
    php = must_get_script("php.sh")
    ssh = must_get_script("ssh.sh")
    backup = must_get_script("initial_backup.sh")
    firewall = must_get_script("firewall_template.sh")
    ident = must_get_script("ident.sh")
    local_pass = must_get_script("pass.sh")
    final = must_get_script("final.sh")

    logger.info("Running PHP hardening")
    run_script_across_hosts(php, hosts=hosts)

    logger.info("Running SSH hardening")
    run_script_across_hosts(ssh, hosts=hosts)

    logger.info("Backing stuff up")
    run_script_across_hosts(backup, ["/root/initial_backs"], hosts=hosts)

    logger.info("Running firewall")
    run_script_across_hosts(
        firewall,
        ["apply"],
        hosts=hosts,
    )

    logger.info("Rotating passwords")
    run_script_across_hosts(local_pass, hosts=hosts)

    logger.info("Downloading backup")
    download_from_ips("/root/initial_backs", hosts)

    logger.info("Running ident")
    run_script_across_hosts(ident, hosts=hosts)

    logger.info("Final")
    run_script_across_hosts(final, hosts=hosts)


def list_hosts():
    config_dict = load_config()
    for ip in config_dict.keys():
        print(config_dict[ip])


def profile_hosts():
    hosts = load_host_list()
    results = get_server_ids(hosts)
    for result in results:
        host = result.host
        id = result.stdout
        if id not in host.tags:
            host.tags.append(result.stdout)
            modify_host(host)
    hostname = must_get_script("hostname.sh")
    results = run_script_across_hosts(hostname)
    for result in results:
        host = result.host
        alias = result.stdout
        if result.error_code == 0:
            if alias not in host.aliases:
                host.aliases.append(result.stdout)
                modify_host(host)


def install_falco(hosts):
    script = must_get_script("falco.sh")
    filename = "falco.tar.gz"
    if not Path(filename).exists():
        logger.info("Downloading falco from falco.org")
        urlretrieve(
            "https://download.falco.org/packages/bin/x86_64/falco-0.40.0-static-x86_64.tar.gz",
            filename=filename,
        )
    else:
        logger.info("Falco already exists, skipping download")

    upload_to_ips(filename, hosts=hosts)
    run_script_across_hosts(script, hosts=hosts)

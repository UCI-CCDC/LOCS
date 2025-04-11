import asyncio
from .ssh import (
    execute_on_hosts,
    parallel_executor,
    test_password_works,
    test_pubkey_works,
    must_get_script,
)
from .portscanner import ServerAddress
from .config_manager import SHORT_TIMEOUT, load_host_list, get_host_from_ip

MAGIC_PORT = 9999


class TestResult:
    def __init__(self, host):
        self.host = host
        self.firewall_test_passed = False
        self.raw_socket_output = ""
        self.pubkey_test_passed = False
        self.default_pass_failed = False
        self.fake_pass_failed = False


async def try_connect_with_timeout(server_address):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(*server_address.get_socket_address()),
            timeout=SHORT_TIMEOUT,
        )
        writer.close()
        return None
    except asyncio.TimeoutError:
        return server_address
    except Exception:
        return None


async def gen_server_address_list():
    hosts = load_host_list()
    server_address_list = [ServerAddress(host.ip, MAGIC_PORT) for host in hosts]
    return server_address_list


async def test_firewall():
    # addr = ServerAddress("10.100.40.34", MAGIC_PORT)
    # x = await try_connect_with_timeout(addr)

    server_address_list = await gen_server_address_list()
    tasks = [
        try_connect_with_timeout(server_address)
        for server_address in server_address_list
    ]
    results = await asyncio.gather(*tasks)
    results = [result for result in results if result is not None]
    return results


def check_for_raw_sockets():
    script = must_get_script("raw_sockets.sh")
    return execute_on_hosts(script)


def get_hosts_with_pass(password):
    hosts = load_host_list()
    for host in hosts:
        host.password = password
    return hosts


def check_password_fail(password):
    hosts = get_hosts_with_pass(password)
    return parallel_executor(test_password_works, hosts)


def check_pubkey_fail():
    hosts = load_host_list()
    return parallel_executor(test_pubkey_works, hosts)


def get_test_results():
    """
    need to first get all the data, and then I will create a dictionary with each host, and all
    the output I need to log for it.
    """
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(loop)
    firewall_test_results = loop.run_until_complete(test_firewall())
    loop.close()
    raw_sockets_results = check_for_raw_sockets()
    pubkey_test_results = check_pubkey_fail()
    print(pubkey_test_results)

    default_pass = "forTheEmper0r!"
    fake_pass = "fake"

    fake_password_results = check_password_fail(fake_pass)
    default_password_results = check_password_fail(default_pass)

    test_results = {}
    for host in load_host_list():
        test_results[host.ip] = TestResult(host.ip)

    for server_address in firewall_test_results:
        test_results[server_address.ip_address].firewall_test_passed = True

    for run_result in raw_sockets_results:
        test_results[run_result.host.ip].raw_socket_output = run_result.stdout

    for host in pubkey_test_results:
        test_results[host.ip].pubkey_test_passed = True

    for login_result in fake_password_results:
        test_results[
            login_result.host.ip
        ].fake_pass_failed = not login_result.successful_login

    for login_result in default_password_results:
        test_results[
            login_result.host.ip
        ].default_pass_failed = not login_result.successful_login
    return test_results


def log_test_results(test_results):
    with open("sanity_test_results.log", "w") as file:
        for ip, result in test_results.items():
            host = get_host_from_ip(ip)
            # Write the results for the current host
            file.write(f"Test results for host {host.name()}:\n")
            file.write(f"Firewall Test Passed: {result.firewall_test_passed}\n")
            file.write(f"Raw Socket Output: {result.raw_socket_output}\n")
            file.write(f"Pubkey Test Passed: {result.pubkey_test_passed}\n")
            file.write(f"Fake Password Failed: {result.fake_pass_failed}\n")
            file.write(f"Default Password Failed: {result.default_pass_failed}\n")
            file.write("-" * 50 + "\n")  # Separator between hosts


def sanity_test():
    test_results = get_test_results()
    log_test_results(test_results)


if __name__ == "__main__":
    sanity_test()

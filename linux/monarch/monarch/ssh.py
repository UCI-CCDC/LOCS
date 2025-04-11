from .monarch_logger import setup_logger
from .config_manager import (
    load_host_list,
    SHORT_TIMEOUT,
    LONG_TIMEOUT,
)
import sys
import tty
import termios
import select
import shutil
import signal
import os
import socket
import paramiko
import io
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from dotenv import dotenv_values

logger = setup_logger("SSH")


class RunResult:
    def __init__(self, host, stdout, stderr, code=None):
        self.host = host
        self.stdout = stdout.read().decode("utf-8").strip()
        self.stderr = stderr.read().decode("utf-8").strip()
        self.error_code = stdout.channel.recv_exit_status() if code is None else code


class LoginResult:
    def __init__(self, host, successful_login):
        self.host = host
        self.successful_login = successful_login


def parallel_executor(target_function, hosts=[], *args, **kwargs):
    results = []
    logger = setup_logger("Parallel Executor")
    if not hosts:
        logger.info("Filtering hosts to ignore router")
        hosts = load_host_list()
        filter = [
            host
            for host in hosts
            if not host.ip.endswith(".1") and not host.ip.endswith(".2")
        ]
    else:
        filter = hosts
    with ThreadPoolExecutor() as executor:
        # Submit all jobs first
        futures = {
            executor.submit(target_function, host, *args, **kwargs): host
            for host in filter
        }

        # Collect results after all tasks are submitted
        for future in futures:
            item = futures[future]  # Retrieve associated item
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error executing on {item.name()}: {e}")

    return results


def get_ssh_client(host):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        host.ip,
        port=host.port,
        username=host.user,
        password=host.password,
        timeout=SHORT_TIMEOUT,
    )
    return ssh


def get_script(name):
    matches = []
    for root, dirs, files in os.walk("scripts/"):
        for file in files:
            path = os.path.join(root, file)
            if name == file:
                matches.append(path)

    if len(matches) == 1:
        return matches[0]
    else:
        return None


def must_get_script(name):
    script = get_script(name)
    if script is None:
        raise ValueError(f"Script {name} was not found")

    return script


def test_password_works(host):
    """return true if password auth is successful"""
    try:
        script = must_get_script("hello.sh")
        result = execute(host, script)
        if result is None or "hello" not in result.stdout:
            return LoginResult(host, False)
        return LoginResult(host, True)
    except Exception:
        return LoginResult(host, False)


def test_pubkey_works(host):
    """return the host if it doesn't support pubkey auth"""
    try:
        transport = paramiko.Transport((host.ip, host.port))
        transport.connect()
        allowed_auths = transport.auth_none("root")
        if "publickey" not in allowed_auths:
            return host
        else:
            return None
    except paramiko.ssh_exception.BadAuthenticationType as e:
        if "publickey" not in str(e):
            return host
        else:
            return None
    except Exception:
        return None
    finally:
        try:
            transport.close()
        except Exception:
            pass


def execute(host, script_path, arguments=[]):
    """Executes a script on the specified host"""
    ssh = get_ssh_client(host)
    logger.info(f"running {script_path} on {host.name()}")

    try:
        with ssh.open_sftp() as sftp:
            filename = Path(script_path).name
            sftp.put(script_path, filename)
            sftp.chmod(filename, 0o700)
            _, stdout, stderr = ssh.exec_command(
                "./" + filename + " " + " ".join(arguments), timeout=LONG_TIMEOUT
            )
        return RunResult(host, stdout, stderr)
    except Exception as e:
        logger.error(f"failed to upload and run {script_path} because: {e}")
        return None
    finally:
        ssh.close()


def get_server_id(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SHORT_TIMEOUT)
        sock.connect((host.ip, host.port))
        id = sock.recv(1024)
        return RunResult(host, io.BytesIO(id), io.BytesIO(b""), 0)
    finally:
        sock.close()


def get_server_ids(hosts=[]):
    return parallel_executor(get_server_id, hosts)


def execute_on_hosts(script_path, arguments=[], hosts=[]):
    return parallel_executor(execute, hosts, script_path, arguments)


def update_terminal_size(chan):
    cols, lines = shutil.get_terminal_size()
    chan.resize_pty(width=cols, height=lines)


def interactive_shell(chan):
    old_settings = termios.tcgetattr(sys.stdin.fileno())

    # Handle window resize
    def sigwinch_handler(sig, data):
        update_terminal_size(chan)

    signal.signal(signal.SIGWINCH, sigwinch_handler)
    update_terminal_size(chan)

    try:
        tty.setraw(sys.stdin.fileno())
        chan.settimeout(0.0)

        envs = dotenv_values(".env")
        for key, val in envs.items():
            chan.send(f"export {key}={val}\n")
        while True:
            r, _, _ = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    data = chan.recv(1024)
                    if len(data) == 0:
                        break
                    os.write(sys.stdout.fileno(), data)
                except socket.timeout:
                    pass
            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if len(data) == 0:
                    break
                chan.send(data)
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)


def spawn_shell(host):
    logger.info(f"ssh {host.user}@{host.ip}")
    logger.info(f"Using password '{host.password}'")
    ssh = get_ssh_client(host)
    channel = ssh.invoke_shell(term="xterm-256color")
    interactive_shell(channel)
    ssh.close()


# def sshpass(host: Host):
#     result = SSHClientWrapper(
#         host=host.ip,
#         user=host.user,              # SSH username
#         password=host.password,      # SSH password
#         # commands="",                   # Empty list for interactive mode
#         invoke_shell=True,             # Must be True for interactive shells
#         prompt="#",                    # Expected prompt character
#         timeout=360,                   # Connection timeout in seconds
#         delay=0.5                      # Delay between commands
#     )


def upload_file(host, local_path):
    ssh = get_ssh_client(host)
    try:
        with ssh.open_sftp() as sftp:
            filename = Path(local_path).name
            sftp.put(local_path, filename)
            sftp.chmod(filename, 0o700)
        logger.info(f"{local_path} succesfully uploaded to {host.name()} at {filename}")
    except Exception as e:
        logger.error(f"Error uploading file to {host.name()}: {e}")
    finally:
        ssh.close()


def download_tar(host, remote_path):
    ssh = get_ssh_client(host)
    try:
        basename = os.path.basename(remote_path)
        logger.info(f"Copying {remote_path} on host {host.name()}")
        _, stdout, stderr = ssh.exec_command(
            f"tar c {remote_path}", timeout=LONG_TIMEOUT
        )
        out = stdout.read()
        err = stderr.read().decode("utf-8")
        code = stdout.channel.recv_exit_status()
        if code != 0:
            logger.error(f"Failed downloading directory from {host.name()}: {err}")
        else:
            obj = io.BytesIO(out)
            path = f"{host.name()}-{basename}"
            os.mkdir(path)
            with tarfile.open(fileobj=obj) as tar:
                tar.extractall(path=path)
            logger.info(f"Finished copying for host {host.name()}")
    except Exception as e:
        logger.error(
            f"Error downloading directory {remote_path} from {host.name()}: {e}"
        )
    finally:
        ssh.close()


def download_from_ips(remote_path, hosts):
    return parallel_executor(download_tar, hosts, remote_path)


def upload_to_ips(local_path, hosts=[]):
    return parallel_executor(upload_file, hosts, local_path)

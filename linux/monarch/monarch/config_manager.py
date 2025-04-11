from pathlib import Path
import json

from .monarch_logger import setup_logger

CONFIG_FILE = Path("conf.json")
# Timeouts, in seconds
# Used for network connections
SHORT_TIMEOUT = 0.5
LONG_TIMEOUT = 15

logger = setup_logger("Config Manager")


class Host:
    def __init__(
        self,
        ip,
        user="root",
        password="",
        aliases=[],
        open_ports=[],
        tags=[],
        port=22,
    ):
        self.ip = ip
        self.user = user
        self.password = password
        self.aliases = aliases
        self.open_ports = open_ports
        self.tags = tags
        self.port = port

    def __repr__(self):
        cls = type(self).__name__
        return f"{cls}(ip={self.ip!r}, user={self.user!r}, password={self.password!r}, port={self.open_ports!r}, aliases={self.aliases!r})"

    def __eq__(self, other):
        if not isinstance(other, Host):
            return NotImplemented
        return (
            self.ip,
            self.user,
            self.password,
            self.open_ports,
            self.aliases,
            self.tags,
        ) == (
            other.ip,
            other.user,
            other.password,
            other.open_ports,
            other.aliases,
            other.tags,
        )

    def __str__(self):
        if len(self.aliases) == 0:
            aliases = ""
        else:
            aliases = ", aliases " + " ".join(self.aliases)
        return f"{self.user}@{self.ip}:{self.port} (password {self.password}{aliases})"

    def name(self):
        if self.aliases:
            return self.aliases[0]
        else:
            return self.ip


def load_config():
    """Loads the configuration file."""
    if not CONFIG_FILE.exists():
        logger.warn(f"Config file not found: {CONFIG_FILE}, creating new file")
        return {}

    with open(CONFIG_FILE, "r") as file:
        config_dict = json.load(file) or {}
        for ip in config_dict.keys():
            config_dict[ip] = Host(**config_dict[ip])
        return config_dict


def save_config(config_dict):
    """Saves the configuration file."""
    for ip in config_dict.keys():
        config_dict[ip] = config_dict[ip].__dict__
    with open(CONFIG_FILE, "w") as file:
        json.dump(config_dict, file, indent=4)


def add_host(host):
    data = load_config()
    data[host.ip] = host
    save_config(data)


def modify_host(host):
    add_host(host)


def remove_host(host):
    data = load_config()
    del data[host.ip]
    save_config(data)


def load_host_list():
    host_dict = load_config()
    return list(host_dict.values())


def get_host_from_ip(ip):
    return load_config()[ip]

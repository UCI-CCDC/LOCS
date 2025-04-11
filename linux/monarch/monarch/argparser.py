from argparse import ArgumentParser, RawDescriptionHelpFormatter


def add_subcmd(
    parser,
    name,
    help,
    alias=None,
    key="cmd",
):
    aliases = [alias] if alias is not None else []
    subcmd = parser.add_parser(name=name, help=help, aliases=aliases)
    # So that I can determine aliases
    subcmd.set_defaults(**{key: name})
    return subcmd


def get_parser():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description="""
            Monarch

            三军可夺帅，匹夫不可夺志
            The commander of the forces of a large state may be carried off,
            but the will of even a common man cannot be taken from him.
        """,
    )

    subparser = parser.add_subparsers()
    # Help
    help = add_subcmd(subparser, "help", "Print help", "h")
    help.add_argument(
        "subcommand", help="Specified subcommand to get help for", nargs="?"
    )
    # Rotate
    rotate = add_subcmd(
        subparser, "rotate", "Change passwords on all hosts, or a specified host"
    )
    rotate.add_argument(
        "host", help="Host to rotate", nargs="?", default=None, type=str
    )
    rotate.add_argument(
        "-p",
        "--password",
        help="Specify a specific password to use for all hosts",
        required=False,
        default=None,
        type=str,
    )
    # Scan
    scan = add_subcmd(subparser, "scan", "Scan all hosts in provided subnets")
    scan.add_argument("subnet", help="Subnet to be scanned (ex. 10.200.1.0/24)")
    scan.add_argument(
        "passwords", help="Default password for the scanned subnet", nargs="+"
    )
    # Base
    base = add_subcmd(
        subparser, "base", "Run initial base on all hosts, or a specified host"
    )
    base.add_argument(
        "host", help="Host to run initial base on", nargs="?", default=None, type=str
    )
    # Shell
    shell = add_subcmd(subparser, "shell", "Get a shell on a host", "sh")
    shell.add_argument("host", help="Host to get a shell to")
    # List
    add_subcmd(subparser, "list", "List all known hosts", "ls")
    # Add
    add = add_subcmd(subparser, "add", "Add a host manually", "a")
    add.add_argument("ip", help="IP of the host to be added")
    add.add_argument("password", help="Password of the host to be added")
    # Edit
    edit = add_subcmd(subparser, "edit", "Edit attributes of a host", "e")
    edit.add_argument("host", help="Host to be edited")
    edit_sp = edit.add_subparsers()
    password = add_subcmd(edit_sp, "password", "Edit a host's password", "pw", "subcmd")
    password.add_argument("password", help="New password")
    alias = add_subcmd(edit_sp, "alias", "Edit a host's alias", "a", "subcmd")
    alias.add_argument("alias", help="New alias")
    port = add_subcmd(edit_sp, "port", "Edit a host's SSH port", "p", "subcmd")
    port.add_argument("port", help="New port")
    # Remove
    rm = add_subcmd(subparser, "remove", "Remove a host from the config file", "rm")
    rm.add_argument("host", help="Host to remove")
    # Script
    script = add_subcmd(
        subparser, "script", "Run a script across all hosts, or a specified host", "sc"
    )
    script.add_argument(
        "-H",
        "--host",
        help="Host to run script on",
        required=False,
        default=None,
        type=str,
    )
    script.add_argument("script", help="Script to run")
    script.add_argument("args", help="Arguments to script", nargs="*", default=None)
    # Upload
    upload = add_subcmd(
        subparser, "upload", "Upload a script to all hosts, or a specified host", "up"
    )
    upload.add_argument("script", help="Script to upload")
    upload.add_argument(
        "host", help="Host to upload the script to", nargs="?", default=None
    )
    # Download
    download = add_subcmd(
        subparser,
        "download",
        "Download a directory as a tar file from all hosts, or a specified host",
        "down",
    )
    download.add_argument("directory", help="Directory or file to download")
    download.add_argument(
        "host", help="Host to download the directory from", nargs="?", default=None
    )
    # Falco
    falco = add_subcmd(
        subparser, "falco", "Install falco on all hosts, or a specified host"
    )
    falco.add_argument("host", help="Host to install falco on", nargs="?", default=None)
    # Profile
    add_subcmd(subparser, "profile", "Profile all hosts", "pr")

    return parser, subparser

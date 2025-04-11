from .passwords import change_root_passwords
from .utils import (
    initialize_hosts,
    run_initial_base,
    run_script_across_hosts,
    get_host,
    maybe_get_host,
    list_hosts,
    profile_hosts,
    install_falco,
)
from .ssh import spawn_shell, upload_to_ips, download_from_ips, get_script
from .config_manager import add_host, modify_host, remove_host, Host


def run(parser, args):
    cmd = args.cmd
    if cmd == "help":
        if args.subcommand is None or args.subcommand == "":
            parser.print_help()
        else:
            try:
                parser.parse_args([args.subcommand, "-h"])
            except SystemExit as e:
                if not e.code == 0:
                    parser.print_help()
    elif cmd == "scan":
        # print(args)
        initialize_hosts([args.subnet], args.passwords)
    elif cmd == "rotate":
        change_root_passwords(args.host, args.password)
    elif cmd == "base":
        run_initial_base(args.host)
    elif cmd == "shell":
        host = get_host(args.host)
        spawn_shell(host)
    elif cmd == "list":
        list_hosts()
    elif cmd == "profile":
        profile_hosts()
    elif cmd == "add":
        add_host(Host(ip=args.ip, password=args.password))
    elif cmd == "remove":
        host = get_host(args.host)
        remove_host(host)
    elif cmd == "edit":
        host = get_host(args.host)
        subcmd = args.subcmd
        if subcmd == "password":
            host.password = args.password
        elif subcmd == "alias":
            host.aliases.append(args.alias)
        elif subcmd == "port":
            port = int(args.port)
            if port <= 0 or port >= 65535:
                raise ValueError(f"Port {port} out of range")
            host.port = port
        else:
            print(args)
            raise ValueError("Command is not one of the valid commands")

        modify_host(host)
    elif cmd == "script":
        hosts = maybe_get_host(args.host)
        script = get_script(args.script)
        if script is None:
            raise ValueError("Script wasn't found under scripts/ directory")
        run_script_across_hosts(script, args.args, hosts)
    elif cmd == "upload":
        hosts = maybe_get_host(args.host)
        script = get_script(args.script)
        upload_to_ips(script, hosts)
    elif cmd == "download":
        hosts = maybe_get_host(args.host)
        download_from_ips(args.directory, hosts)
    elif cmd == "falco":
        hosts = maybe_get_host(args.host)
        install_falco(hosts)
    else:
        print(args)
        raise ValueError("Command is not one of the valid commands")


if __name__ == "__main__":
    pass
    # initialize_hosts(["10.100.40.0/24"], ["forTheEmper0r!"])
    # hosts = config_manager.load_host_list()
    # host = hosts[1]
    # host.aliases.append("caliban")
    # config_manager.modify_host(host)
    # host= utils.get_host('cal')
    # data = config_manager.load_config()

    # passwords.change_all_root_passwords()

    # host = Host(**data["10.100.40.34"])
    # ssh.sshpass(host)
    # ssh.spawn_shell(host)
    # execute("scripts/test.sh", [])
    # results = ssh.execute_on_hosts('scripts/test.sh')
    # for result in results:
    #     print(result.__dict__)

from argparse import ArgumentParser
from pathlib import Path
from manager import LdapManager

LDAP_CONFIG_PATH = Path('ldap.conf')

def parse_config():
    host_dict = {}
    with open(LDAP_CONFIG_PATH, 'r') as file:
        lines = file.readlines()

    for line in lines:
        l = line.strip().split(' ', maxsplit = 2)
        if len(l) == 3:
            host_dict[l[0]] = (l[1], l[2])
        elif len(l) == 1:
            host_dict[l[0]] = ''

    return host_dict

def add_host_to_config(host_ip):
    f = open(LDAP_CONFIG_PATH, 'a')
    f.write(f'{host_ip}\n')
    f.close()

def set_admin(host_ip, admin_dn, admin_password):
    with open(LDAP_CONFIG_PATH, 'r') as file:
        lines = file.readlines()
    for i, line in enumerate(lines):
        parts = line.split()
        if parts[0] == host_ip:
            lines[i] = f'{host_ip} {admin_dn} {admin_password}\n'
    with open(LDAP_CONFIG_PATH, 'w') as file:
        file.writelines(lines)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--host", help = 'IP address of LDAP server', type=str, required=True)
    parser.add_argument("--set-admin", help = 'Set the admin user: --set-admin admin_dn:admin_password', type=str)
    parser.add_argument("--list-users", action = 'store_true', help = 'List all users')
    parser.add_argument("--set-password", help=f'Set password of user: --set-password user_dn:new_pass', type=str)
    parser.add_argument("--rotate-passwords", help=f'Set password of all users and output to file: --rotate-password out.csv', type=str)
    parser.add_argument("--list-nodes", action = 'store_true', help = 'List all node DNs')
    parser.add_argument("--inspect", help = 'Inspect node: --inspect node_dn', type=str)

    args = parser.parse_args()



    host_dict = parse_config()
    if args.host not in host_dict:
        add_host_to_config(args.host)

    if args.set_admin:
        set_admin(args.host, *(args.set_admin.split(':')))
        host_dict[args.host] = tuple(args.set_admin.split(':'))


    manager = LdapManager(args.host)
    print(f'SEARCH BASE: {manager.get_search_base()}')

    if host_dict[args.host]:
        manager.login_to_user(*host_dict[args.host])

    if args.list_users:
        manager.get_all_users()

    if args.set_password:
        manager.change_user_password(*args.set_password.split(':'))

    if args.rotate_passwords:
        manager.rotate_user_passwords(args.rotate_passwords)

    if args.list_nodes:
        manager.list_all_dn()

    if args.inspect:
        manager.inspect_node(args.inspect)












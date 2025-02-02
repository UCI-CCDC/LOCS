import ldap3
from ldap3 import Server, Connection, ALL, DsaInfo
import secrets
import string
class LdapManager:

    def __init__(self, ip_addr):
        self._ip_addr = ip_addr
        self._server = Server(ip_addr, get_info = ALL)
        self._conn = Connection(self._server, auto_bind = True)
        self._search_base = self._server.info.naming_contexts[0]

    def get_search_base(self):
        return self._search_base

    def get_all_users(self):
        try:
            possible_admins = []
            print('Users:')
            for entry_dn in self._list_users_dn():
                print(entry_dn)
                if 'admin' in entry_dn:
                    possible_admins.append(entry_dn)

            print('Possible Admins:')
            for admin in possible_admins:
                print(admin)
        except ValueError:
            print('Error has occurred in getting persons')

    def _list_users_dn(self):
        if self._conn.search(self._search_base, '(objectclass=person)'):
            for entry in self._conn.entries:
                entry_dn = entry._state.dn
                yield entry_dn
        else:
            raise ValueError()

    def list_all_dn(self):
        if self._conn.search(self._search_base, '(objectClass=*)', attributes = ['dn']):
            for entry in self._conn.entries:
                entry_dn = entry._state.dn
                print(entry_dn)
        else:
            raise ValueError()

    def login_to_user(self, user_dn, user_password):
        try:
            self._conn = Connection(self._ip_addr, user_dn, user_password, auto_bind=True)
        except ldap3.core.exceptions.LDAPBindError:
            print('Invalid credentials.')
        else:
            print('Successfully logged in')

    def change_user_password(self, dn, new_password):
        x = self._change_pass(dn, new_password)
        if x:
            print('Successfully changed user password')
        else:
            print('Unable to change user password. Make sure you have proper privileges.')

    def rotate_user_passwords(self, filepath):
        with open(filepath, 'w') as file:
            for user_dn in self._list_users_dn():
                new_pass = ''.join(secrets.choice(string.ascii_letters + string.digits)for _ in range(15))
                changed = self._change_pass(user_dn, new_pass)
                if changed:
                    x = user_dn.split(',')
                    user_uid = x[0][4:]
                    creds = f'{user_uid},{new_pass}'
                    print(creds)
                    file.write(creds + '\n')
                else:
                    print('Failed to change password of user:', user_dn)


    def _change_pass(self, dn, password):
        return self._conn.modify(dn, {'userPassword': [(ldap3.MODIFY_REPLACE, [password])]})


    def inspect_node(self, dn):
        if self._conn.search(search_base=dn,
    search_filter= '(objectClass=*)', # required
    search_scope=ldap3.BASE,
    attributes='*'):
            print(self._conn.entries[0].entry_to_ldif())
        else:
            raise ValueError()
    



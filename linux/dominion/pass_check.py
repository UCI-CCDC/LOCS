import utils
import argparse
from pathlib import Path
import time

LOG_FILE_NAME = 'pass_check.log'

def test_default_on_all_hosts(default_password: str):
    '''tests default on all hosts, and writes results to the pass_check.txt file '''
    while(True):

        data = utils.read_all()
        output = ''
        for ip in data.keys():
            host = data[ip]
            
            default_fails = default_fails_on_host(host, default_password)
            if default_fails:
                output += f'SUCCESS ON {host.name()}\n'
            else:
                output += f'FAILED ON {host.name()}\n'


        file_path = Path(LOG_FILE_NAME)


        with file_path.open("w") as f:
            f.write(output)

        time.sleep(300)




def default_fails_on_host(host: utils.Host, default_password: str) -> bool:
    '''return true if the default password fails on the host'''
    host.password = default_password

    try:
        utils.get_ssh_client(host)
    except Exception:
        return True #default failed, so it is an exception 
    else:
        return False






if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='a script that runs in the background and checks if the default password work on any machine every 5 minutes. Sample execution: nohup python3 pass_check.py DEFAULT_PASS &')
    
    parser.add_argument("default_password", help="The default password to test all machines with", type=str)
    args = parser.parse_args()

    test_default_on_all_hosts(args.default_password)






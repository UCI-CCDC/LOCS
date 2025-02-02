#!/usr/bin/env python

import dominion
import printer
import utils

def initial_base_across_boxes():
    BACKUP_PATH = input("Enter the path to backup the initial base to (default /etc/backup/): ") or '/etc/backup'
    QUIET = utils.yes_or_no("Do you want to run backup in quiet mode? (y/n): ")
    
    env_vars = [BACKUP_PATH]
    if QUIET:
        env_vars.append("QUIET")
    env_vars = utils.map_args_to_env_vars(env_vars)

    #initial hardening scripts
    utils.run_script_against_all_hosts("../linux-hardening/php.sh")
    utils.run_script_against_all_hosts("../linux-hardening/ssh.sh")
    utils.run_script_against_all_hosts("../linux-hardening/lockdown.sh")

    #upload firewall template
    firewall_template_local_path='../linux-toolbox/firewall/firewall_template.sh'
    firewall_template_remote_path='/root/firewall_template.sh'
    utils.upload_to_ips(firewall_template_local_path, firewall_template_remote_path)



    utils.run_script_against_all_hosts_with_env_vars("../linux-toolbox/initial_backup.sh", env_vars)

    printer.message(f"Initial base ran on all hosts with backup path {BACKUP_PATH}", dominion.SUCCESS)

    #run ident.sh
    utils.run_script_against_all_hosts("../linux-inventory/ident.sh")

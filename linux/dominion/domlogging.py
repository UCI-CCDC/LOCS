#!/usr/bin/env python

import dominion
import printer
import utils

def logging_across_boxes(data: dict):
    GRAYLOG_IP = input("Enter the IP of the Graylog server: ")

    for ip, host in data.items():
        utils.run_script(host, "../linux-toolbox/logging.sh", utils.map_args_to_env_vars([GRAYLOG_IP]))
        printer.message(f"Ran logging.sh on {ip} with Graylog IP {GRAYLOG_IP}", dominion.SUCCESS)
        utils.log(f"Ran logging.sh on {ip} with Graylog IP {GRAYLOG_IP}")

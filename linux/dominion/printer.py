#!/usr/bin/env python
import dominion

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    PURPLE = '\033[35m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def message(string: str, type=None) -> None:
    if type == dominion.ERROR:
        print(bcolors.FAIL + f"[ERROR] {string}" + bcolors.ENDC)
    elif type == dominion.WARNING:
        print(bcolors.WARNING + f"[WARNING] {string}" + bcolors.ENDC)
    elif type == dominion.SUCCESS:
        print(bcolors.OKGREEN + f"[SUCCESS] {string}" + bcolors.ENDC)
    else: 
        print(bcolors.OKBLUE + f"[DOMINION] {string}" + bcolors.ENDC)

def print_banner() -> None:
    print(bcolors.PURPLE + r"""
     .
                       .       |         .    .
                 .  *         -*-          *
                      \        |         /   .
     .    .            .      /^\     .              .    .
        *    |\   /\    /\  / / \ \  /\    /\   /|    *
     .    .  |  \ \/ /\ \ / /     \ \ / /\ \/ /  | .     .
              \ | _ _\/_ _ \_\_ _ /_/_ _\/_ _ \_/
                \  *  *  *   \ \/ /  *  *  *  /
                 ` ~ ~ ~ ~ ~  ~\/~ ~ ~ ~ ~ ~ '
          

▓█████▄  ▒█████   ███▄ ▄███▓ ██▓ ███▄    █  ██▓ ▒█████   ███▄    █ 
▒██▀ ██▌▒██▒  ██▒▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▓██▒▒██▒  ██▒ ██ ▀█   █ 
░██   █▌▒██░  ██▒▓██    ▓██░▒██▒▓██  ▀█ ██▒▒██▒▒██░  ██▒▓██  ▀█ ██▒
░▓█▄   ▌▒██   ██░▒██    ▒██ ░██░▓██▒  ▐▌██▒░██░▒██   ██░▓██▒  ▐▌██▒
░▒████▓ ░ ████▓▒░▒██▒   ░██▒░██░▒██░   ▓██░░██░░ ████▓▒░▒██░   ▓██░
 ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒ ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
 ░ ▒  ▒   ░ ▒ ▒░ ░  ░      ░ ▒ ░░ ░░   ░ ▒░ ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
 ░ ░  ░ ░ ░ ░ ▒  ░      ░    ▒ ░   ░   ░ ░  ▒ ░░ ░ ░ ▒     ░   ░ ░ 
   ░        ░ ░         ░    ░           ░  ░      ░ ░           ░ 
 ░                                                                 
     Throughout Heaven and Earth, We Alone Are The Honored Ones
          
""" + bcolors.ENDC, end='')

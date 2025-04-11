#!/usr/bin/env python

from .repl import repl
from .cli import run
from .argparser import get_parser, add_subcmd


def main():
    parser, subparser = get_parser()
    add_subcmd(subparser, "repl", "Enter monarch repl")
    args = parser.parse_args()
    cmd = args.cmd
    if cmd is None:
        parser.print_help()
        return
    elif cmd == "repl":
        repl()
    else:
        run(parser, args)


if __name__ == "__main__":
    main()

import readline
import atexit
from pathlib import Path
from traceback import print_exc

from .argparser import get_parser, add_subcmd
from .cli import run

histfile = ".monarch_history"


def repl():
    if Path(histfile).exists():
        readline.read_history_file(histfile)

    parser, subparser = get_parser()
    add_subcmd(subparser, "exit", "Exit REPL")

    while True:
        try:
            line = input("> ")
            parsed = parser.parse_args(line.strip().split(" "))
            if parsed.cmd == "exit":
                return
            else:
                run(parser, parsed)
        except SystemExit:
            # Probably didn't write a valid command
            pass
        except EOFError:
            # No more input, exit loop
            return
        except KeyboardInterrupt:
            # Ctrl+C, just keep going
            continue
        except Exception:
            print_exc()


atexit.register(readline.write_history_file, histfile)

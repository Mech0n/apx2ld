import cmd
from os.path import basename, splitext
from typing import IO

from rich.console import Console

from utils.apx import apx
from utils.CodeParse import Code_Parse
from utils.Output import Output

"""
    Convert a series of zero or more numbers to an argument tuple
"""


def parse(arg):
    return tuple(arg.split())


class CLI(cmd.Cmd):
    def __init__(self) -> None:
        super().__init__()
        self.prompt = "> "  # define command prompt

        self.apx = None
        self.cp = None

    def do_load(self, arg) -> None:
        "load: Load apx file"
        args = parse(arg)
        if len(args) != 1 and type(args) != str:
            with Console() as c:
                c.print(f"[Module] Cli [Method] do_load: args nums errors!")
            return None

        self.apx = apx(*args)

    def do_analyze(self, arg) -> None:
        "analyze: analyze apx file after load"
        args = parse(arg)
        flag = [x for x in "czao"]
        if self.apx is None:
            with Console() as c:
                c.print(
                    f"[Module] Cli [Method] do_release: apx file not loaded, You need load apx file first!"
                )
            return

        self.apx.extract_code()
        self.cp = Code_Parse(self.apx.code, self.apx.extract_LDExchangeFile(), flag)

    def do_release(self, arg) -> None:
        "releas: releas result after release"
        args = parse(arg)
        if self.apx is None:
            with Console() as c:
                c.print(
                    f"[Module] Cli [Method] do_release: apx file not loaded, You need load apx file first!"
                )
            return

        if self.cp is None:
            with Console() as c:
                c.print(f"[Module] Cli [Method] do_release: You need analyze first!")
            return

        filename = basename(self.apx.filename)
        release = Output(splitext(filename)[0])
        ld_trees = self.cp.get_as_bitree()

        release.visualize_tree(ld_trees)
        release.save_img()

    def do_quit(self, arg):
        "Just quit the shell"
        exit(0)


if __name__ == "__main__":
    banner = """
     ___   _____  __    __  _____   _       _____  
    /   | |  _  \ \ \  / / /___  \ | |     |  _  \ 
   / /| | | |_| |  \ \/ /   ___| | | |     | | | | 
  / / | | |  ___/   }  {   /  ___/ | |     | | | | 
 / /  | | | |      / /\ \  | |___  | |___  | |_| | 
/_/   |_| |_|     /_/  \_\ |_____| |_____| |_____/ 

    """
    cli = CLI()
    cli.cmdloop(intro=banner)

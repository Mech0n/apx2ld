import cmd
from typing import IO
from os.path import splitext, basename

from utils.CodeParse import Code_Parse
from utils.Output import Output
from utils.apx import apx

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
        args = parse(arg)
        print(len(args))
        if len(args) != 1 and type(args) != str:
            # TODO: Error msg
            return None

        self.apx = apx(*args)

    def do_analyze(self, arg) -> None:
        args = parse(arg)
        flag = [x for x in "czao"]
        if self.apx is None:
            # TODO: Error msg
            return 

        self.apx.extract_code()
        self.cp = Code_Parse(self.apx.code, self.apx.extract_LDExchangeFile(), flag)

    def do_release(self, arg) -> None:
        args = parse(arg)
        if self.apx is None:
            # TODO: Error msg
            return 

        if self.cp is None:
            # TODO: Error msg
            return

        filename = basename(self.apx.filename)
        release = Output(splitext(filename)[0])
        ld_trees = self.cp.get_as_bitree()

        release.visualize_tree(ld_trees)
        release.save_img()
        


    def do_quit(self, arg):
        exit(0)

if __name__ == "__main__":
    cli = CLI()
    cli.cmdloop(intro="welcome to apx2ld")
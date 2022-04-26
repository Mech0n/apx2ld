from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from copy import deepcopy

from .Instructions import *
from .Operand import Operand
from .PLCInstructions import Variable, FBD
from .x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from .Register import register
from .DataStruct import Node


class CodeParse (object):
    def __init__(self, code, flags) -> None:
        self.code = code
        self.cCode = ""

        # Instruction lookup
        self.cinstr = {
            "mov": mov,
            "movzx": movzx,
            "movsx": movzx,
            "cdqe": cdqe,
            "sub": sub,
            "add": add,
            "inc": inc,
            "dec": dec,
            "cmp": cmp,
            "jmp": jmp,
            "jne": jne,
            "je": je,
            "jnb": jnb,
            "jb": jb,
            "jbe": jbe,
            "enter": enter,
            "xor": xor,
            "and": and_,
            "push": push,
            "pop": pop,
            "or": or_,
            "call": call,
            "leave": leave,
            "ret": ret,
            "not": not_,
            "shr": shr,
            "rcl": rcl,
        }

        """
        {
            "addr" : {tag1: value, tag2: value},
            "addr" : {tag1: value, tag2: value},
        }
        """
        self.variables = dict()
        self.recent_variable_base = 0
        self.function_variable_base = 0
        self.function_variable_flag = False

        """
        functions : only save the functions base address and bx value
        {
            disp: [FBD, ],
            disp: [FBD, ]
        }
        """
        self.functions = dict()
        self.recent_fbd = None

        """
        "ebx" : reg
        """
        self.regs = dict()
        self.init_regs()

        """
        each rung
        """
        self.rungs = []
        self.rung = []

        self.jumps = ["jmp", "je", "jne", "jz", "jnz", "jnb", "jb", "jbe"]
        self.usedFlags = flags

        # Init capstone
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.instructions = [x for x in self.cs.disasm(self.code, 0)]

        self.jumpPlaces = {}
        self.check_jumps()

        self.find_function_base()

        self.run()

        print(self.rungs)
        self.get_as_bitree()
        self.functions_log()


    """
        transform rungs to ladder logic as bi-tree
        - or    : each node has an or relationship with right node
        - and   : each node has an and relationship with left node
    """
    # TODO transplant to output module
    def get_as_bitree(self) -> list:
        bitrees = []
        stack = []
        head = None
        for rung in self.rungs:
            if len(rung) == 0:
                continue                
            for elem in rung:
                if elem == 'Contact':
                    tmp = Node(elem)
                    stack.append(tmp)
                elif elem in ['and', 'or']:
                    tmp = Node(elem)
                    tmp.left = stack.pop()
                    tmp.right = stack.pop()
                    stack.append(tmp)
                else:
                    # TODO: something else about the other PLC instructions
                    pass
                
            head = stack.pop()
            bitrees.append(head)

            stack.clear()

            def printTree(node, level=0):
                if node != None:
                    printTree(node.left, level + 1)
                    print(' ' * 4 * level + '-> ' + node.value)
                    printTree(node.right, level + 1)
            
            printTree(head)
            print()
            head = None
        
        return bitrees

    """ 
        Every jump must have place to jump,
        here we check, that every jump has place,
        if code is self-modyifing or jumps in middle of instruction
        then this method will fail
    """

    def check_jumps(self):
        for instr in self.instructions:

            # Is it jump?
            if instr.mnemonic in self.jumps:

                # Yes, so get address
                addr = int(instr.operands[0].imm)
                found = False

                # Check existence of target instruction
                for _instr in self.instructions:
                    if _instr.address == addr:
                        found = True
                        self.jumpPlaces[addr] = True
                        break

                if not found:
                    print(
                        "Jump to nonexisting instr (Or jump in instr middle)...\nQuitting..."
                    )
                    exit(0)

    """ 
        Go over each instruction in range 
    """

    def run(self):
        for inst in self.instructions:
            print(f"logs : {inst.mnemonic}\t{inst.op_str}")

            # If we will jump to this instruction
            # Add label for goto
            if inst.address in self.jumpPlaces:
                self.add_log(f"_{hex(inst.address)}:", indent=0)

            # Operands is list of ops, 0, 1, 2 (may more) ops
            ops = [x for x in inst.operands]
            args = [self.build_operand(inst, x) for x in ops]

            # check Instruction is available
            if inst.mnemonic not in self.cinstr:
                print("Instruction not found...\nQuitting...")
                exit(0)

            # process instruction
            self.cinstr[inst.mnemonic](*args, inst, self)

    """ 
        Create Operand
    """

    def build_operand(self, instr, operand):
        operand_type = operand.type
        # print(f"logs : {operand.size}")

        # eg. regs.eax
        if operand_type == X86_OP_REG:
            # print(instr.reg_name(operand.reg))
            return Operand(operand_type, instr.reg_name(operand.reg), operand.size)

        # eg. rax + rbx * 1 - 0x13
        if operand_type == X86_OP_MEM:
            baseReg = instr.reg_name(operand.mem.base)
            displacement = operand.mem.disp  # adddress
            index, scale = (operand.mem.index, operand.mem.scale)

            if baseReg != None:
                out = baseReg

                # init variable
                if not index and baseReg in ["rbx", "ebx"] and displacement > 0:
                    if displacement not in self.variables[self.recent_variable_base]:
                        self.variables[self.recent_variable_base][displacement] = Variable(displacement)

            else:
                out = ""
                # find variables
                if displacement > 0x4000000:
                    variable_key = str(displacement)
                    if variable_key not in self.variables:
                        self.variables[variable_key] = dict()
                    if self.recent_variable_base == self.function_variable_base and variable_key != self.function_variable_base:
                        # insert FBD in self.functions
                        tmp = deepcopy(self.recent_fbd)
                        if self.regs['ebx'].value not in self.functions:
                            self.functions[self.regs['ebx'].value] = []
                        self.functions[self.regs['ebx'].value].append(tmp)    # bx is self.regs['ebx'].value and it's disp and tag.
                        self.recent_fbd = None
                    self.recent_variable_base = variable_key

            if index:
                out += "+" + instr.reg_name(index) + "*" + str(scale)

            if displacement:
                if displacement < 0:
                    out += "-"
                if displacement > 0:
                    out += "+"
                out += str(hex(abs(displacement)))

                # init funcs
                if displacement == 0x4000000:
                    #TODO funcs
                    pass
            
            # print(out)
            return Operand(operand_type, out, operand.size)

        # eg. 0x10
        if operand_type == X86_OP_IMM:
            return Operand(operand_type, str(operand.imm), operand.size)

        raise Exception("Unknown type...")

    """
        Spaces FTW
    """

    def add_log(self, data, flags="", actions="", comment="", indent=1):
        self.cCode += "    " * indent
        self.cCode += data + "; "

        # Append comment
        if len(comment):
            self.cCode += f"// {comment} \n"

        # Check is flag used, and append
        if len(flags):
            for (id, flag) in flags:
                if id in self.usedFlags:
                    self.cCode += ("    " * indent) + "  " + flag + ";\n"

        # Add actions, executed after setting flags
        if len(actions):
            for action in actions:
                self.cCode += ("    " * indent) + "    " + action + ";\n"

        if len(comment) == 0 and len(flags) == 0:
            self.cCode += "\n"

    def init_regs(self) -> None:
        for reg_name in ['eax', 'ebx', 'ecx', 'edx'] :
            self.regs[reg_name] = register(reg_name)

    def find_function_base(self) -> None:
        recent_base = 0
        for inst in self.instructions:
            # find variable base
            p = compile('ebx, dword ptr \\[0x4000[0-9]+\\]')
            m = p.match(inst.op_str)
            if m:
                key = m.group()[16:-1]
                recent_base = int(key, 16)
            
            # set function_variable_base
            if inst.mnemonic == 'call' and inst.op_str == 'ebx':
                self.function_variable_base = str(recent_base)

    def functions_log(self) -> None:
        for key, value in self.functions.items():
            for fbd in value:
                print(f"{key}:")
                print("output:")
                for i in fbd.output_list:
                    print(hex(i))
                print("input:")
                for i in fbd.input_list:
                    print(hex(i))
                print(f"time:\t{fbd.time}")
                print()
            
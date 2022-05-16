from copy import deepcopy
from re import compile

from .PLCInstructions import FBD
from .x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

# Overflow flag mask
ofMask = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}

# X86_OP_MEM default value
mem_default_value = 1

""" 
    Instructions in C implementation
"""


def mov(left, right, inst, cg):

    # set output variable, such as : mov byte ptr [ebx + 0xc], al/dl / mov dword ptr [ebx + 0xc], eax
    if left.type == X86_OP_MEM:
        p = compile('ebx\\+0x[0-9a-fA-F]+')
        m = p.match(left.value)
        if m:
            key = int(m.group()[4:], 16)    # key is disp
            # insert variable in cg.variable
            if int(m.group()[4:], 16) in cg.variables[cg.recent_variable_base]:
                cg.variables[cg.recent_variable_base][key].setOutputFlag(True)

            if cg.recent_variable_base != cg.function_variable_base:
                # maybe it's a coil
                # deal with postfix expression
                cg.rung_end = True
                cg.rung.append(f"disp_{hex(key)}")
                cg.rung.append(cg.coils.pop(0))
                # cg.rung.append('coil')
                cg.rung.append('and')

                # cg.rung.append(f"disp_{hex(key)}")
                # cg.rung.append('coil')
                # cg.rung.append('and')
                # cg.rungs.append(deepcopy(cg.rung))
                # cg.rung.clear()

            else :
                if right.type == X86_OP_REG and right.value in ['al', 'eax']:
                    # maybe it's someone's parameter
                    # which value is {cg.regs['eax'].value}
                    cg.recent_fbd.insert_input_list(key)

                    # TODO: FBD time
                    if right.value == 'eax' and left.sizeBytes == 4:
                        if cg.recent_fbd != None:
                            cg.recent_fbd.set_time(int(cg.regs['eax'].value))
                        else:
                            cg.recent_fbd = FBD()


    # set input variable
    if left.type == X86_OP_REG and left.value in ['eax', 'al']:
        # set input variable, such as : mov eax, dword ptr [ebx + 0xc], mov al, byte ptr [ebx + 0xc]
        if right.type == X86_OP_MEM:
            # set register
            p = compile('ebx\\+0x[0-9a-fA-F]+')
            m = p.match(right.value)
            if m:
                cg.not_flag = False

                key = int(m.group()[4:], 16) # key is disp
                # insert variable in cg.variable
                if key in cg.variables[cg.recent_variable_base]:
                    cg.variables[cg.recent_variable_base][key].setInputFlag(
                        True)
                # set al an assumptive value which is can be find in mem
                cg.regs['eax'].set_value_u8(int(mem_default_value))

                # decide if contact
                if cg.recent_variable_base != cg.function_variable_base:
                    # maybe it's a contact
                    # append postfix expression
                    try:
                        if cg.rung_end == True:
                            cg.rung_end = False
                            # decided a single rung
                            cg.rungs.append(deepcopy(cg.rung))
                            cg.rung.clear()
                        # cg.rung.append('Contact')
                        cg.rung.append(f"disp_{hex(key)}")
                        cg.rung.append(cg.contacts.pop(0))
                    except Exception as e:
                        # TODO: Error msg
                        cg.rung.append(f"disp_{hex(key)}")
                        cg.rung.append('Contact')

                    # try:
                    #     # cg.rung.append('Contact')
                    #     cg.rung.append(f"disp_{hex(key)}")
                    #     cg.rung.append(cg.contacts.pop(0))
                    # except Exception as e:
                    #     # TODO: Error msg
                    #     cg.rung.append(f"disp_{hex(key)}")
                    #     cg.rung.append('Contact')
                else:
                    # maybe it's someone instruction's output
                    cg.recent_fbd.insert_output_list(key)
                return
            
            p = compile('ebp-[0-9a-fA-Fx]+')
            m = p.match(right.value)
            if m:
                cg.not_flag = True


        # handle eax for funcs parameter, such as : mov eax, 0x1222
        elif right.type == X86_OP_IMM:
            cg.regs['eax'].set_value_u32(int(right.value))
            # maybe it's someone's parameter, which value is {cg.regs['eax'].value}

            # if cg.recent_fbd != None:
            #     cg.recent_fbd.set_time(int(right.value))
            # else:
            #     cg.recent_fbd = FBD()
    
    if left.type == X86_OP_REG and left.value in ['bx', 'ebx']:
        if left.value == 'bx' and right.type == X86_OP_IMM:
            # save FBD disp in ebx, such as mov bx, 0x64
            cg.regs['ebx'].set_value_u16(int(right.value))
            cg.recent_fbd.set_disp(right.value)
            
            # Update functions
            # cg.rung.append('Instruction')
            cg.rung.append(str(cg.recent_fbd.disp))
            cg.rung.append('and')

        if left.value == 'ebx' and right.type == X86_OP_MEM:
            # init FBD
            p = compile('\\+0x400[0-9]+')
            m = p.match(right.value)
            if m:
                key = str(int(m.group()[1:], 16))
                if key == cg.function_variable_base:
                    if not cg.function_variable_flag:
                        cg.recent_fbd = FBD()
                        cg.function_variable_flag = True
                    else:
                        cg.function_variable_flag = False


def movzx(left, right, inst, cg):
    pass


def sub(left, right, inst, cg, isCmp=False):
    pass


def add(left, right, inst, cg):
    pass


def inc(left, inst, cg):
    pass


def dec(left, inst, cg):
    pass


def cdqe(inst, cg):
    pass


def cmp(left, right, inst, cg):
    # cmp is sub without setting value
    sub(left, right, inst, cg, True)


def jmp(op, inst, cg):
    pass


def jne(op, inst, cg):
    pass


def je(op, inst, cg):
    pass


def jb(op, inst, cg):
    pass


def jbe(op, inst, cg):
    pass


def jnb(op, inst, cg):
    pass


def enter(left, right, inst, cg):
    pass


def and_(left, right, inst, cg):
    # append postfix expression
    if left.value == 'al' and right.value == 'cl':
        cg.rung.append('and')


def push(op, inst, cg):
    pass


def pop(op, inst, cg):
    pass


def or_(left, right, inst, cg):
    # append postfix expression
    if left.value == 'al' and right.value == 'cl':
        cg.rung.append('or')


def xor(left, right, inst, cg):
    # append postfix expression
    if left.value == 'al' and right.value == 'cl':
        cg.rung.append('xor')


def shr(left, right, inst, cg):
    pass


def rcl(left, right, inst, cg):
    pass


def call(op, inst, cg):
    # mark a PLC instruction
    if op.type == X86_OP_REG and op.value == 'ebx':
        # someone PLC instruction will be use.
        pass



def not_(op, inst, cg):
    # handle eax
    if op.type == X86_OP_REG and op.value == 'eax':
        cg.regs['eax'].set_value_u32(cg.regs['eax'].value)
        # eax is {cg.regs['eax'].value}

        # identify not Logic gate
        if cg.not_flag:
            cg.rung.append('not')


def test(left, right, inst, cg):
    # avoid EN disturb identifying `not` logic gate
    if left.value == 'eax' and right.value == 'eax' and cg.not_flag:
        if cg.rung[-1] == 'not':
            cg.rung.pop()


def leave(op, inst):
    pass


def ret(op, inst):
    pass

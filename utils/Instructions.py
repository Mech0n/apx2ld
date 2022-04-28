from re import compile
from copy import deepcopy

from .x86_const import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
from .PLCInstructions import FBD

# Overflow flag mask
ofMask = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}

# X86_OP_MEM default value
mem_default_value = 1

""" 
    Instructions in C implementation
"""


def mov(left, right, inst, cg):
    payload = f"{inst.mnemonic}\t{inst.op_str};"

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
                payload += "\t maybe it's a coil\n\n"
                # deal with postfix expression
                cg.rung.append('coil')
                cg.rung.append('and')
                cg.rungs.append(deepcopy(cg.rung))
                cg.rung.clear()
            else :
                if right.type == X86_OP_REG and right.value in ['al', 'eax']:
                    payload += "\t maybe it's someone's parameter"
                    payload += f", which value is {cg.regs['eax'].value}"
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
                    payload += "\t maybe it's a contact"
                    # append postfix expression
                    try:
                        # cg.rung.append('Contact')
                        cg.rung.append(cg.contacts.pop(0))
                    except Exception as e:
                        # TODO: Error msg
                        cg.rung.append('Contact')
                else:
                    payload += f"\t maybe it's someone instruction's output"
                    cg.recent_fbd.insert_output_list(key)
                return
            
            p = compile('ebp-[0-9a-fA-Fx]+')
            m = p.match(right.value)
            if m:
                cg.not_flag = True


        # handle eax for funcs parameter, such as : mov eax, 0x1222
        elif right.type == X86_OP_IMM:
            cg.regs['eax'].set_value_u32(int(right.value))
            payload += f" maybe it's someone's parameter, which value is {cg.regs['eax'].value}"

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


    cg.add_log(
        "%s = %s" % (left.getValue(), right.getValue()),
        comment=payload,
    )


def movzx(left, right, inst, cg):
    cg.add_log(
        "%s = 0, %s = %s" % (left.getValue(
            8), left.getValue(), right.getValue()),
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def sub(left, right, inst, cg, isCmp=False):
    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = (left.getValue(), right.getValue())

    if isCmp:
        actions = []
    else:
        actions = ["%s = tmp%s" % (lVal, sizeBits)]

    cg.add_log(
        "TMP%s(%s, -, %s)" % (sizeBits, lVal, rVal),
        flags=[
            ["c", "SET_CF_SUB(%s, %s)" % (lVal, rVal)],
            ["z", "SET_ZF(%s)" % (sizeBits)],
            ["a", "SET_AF_0(%s, %s)" % (left.getValue(1), right.getValue(1))],
            [
                "o",
                "SET_OF_SUB(%s, %s, %s, %s)"
                % (lVal, rVal, sizeBits, hex(ofMask[sizeBytes])),
            ],
        ],
        actions=actions,
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def add(left, right, inst, cg):
    payload = f"{inst.mnemonic}\t{inst.op_str};"

    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = (left.getValue(), right.getValue())

    cg.add_log(
        "TMP%s(%s, +, %s)" % (sizeBits, lVal, rVal),
        flags=[
            ["c", "SET_CF_ADD(%s, %s)" % (sizeBits, lVal)],
            ["z", "SET_ZF(%s)" % (sizeBits)],
            ["a", "SET_AF_0(%s, %s)" % (left.getValue(1), right.getValue(1))],
            [
                "o",
                "SET_OF_ADD(%s, %s, %s, %s)"
                % (lVal, rVal, sizeBits, hex(ofMask[sizeBytes])),
            ],
        ],
        actions=["%s = tmp%s" % (lVal, sizeBits)],
        comment=payload,
    )


def inc(left, inst, cg):
    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = left.getValue(), "1"

    cg.add_log(
        "TMP%s(%s, +, %s)" % (sizeBits, lVal, rVal),
        flags=[
            ["z", "SET_ZF(%s)" % (sizeBits)],
            ["a", "SET_AF_INC(%s)" % (sizeBits)],
            ["o", "SET_OF_INC_DEC_NEG(%s, %s)" % (
                sizeBits, hex(ofMask[sizeBytes]))],
        ],
        actions=["%s = tmp%s" % (lVal, sizeBits)],
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def dec(left, inst, cg):
    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = left.getValue(), "1"

    cg.add_log(
        "TMP%s(%s, -, %s)" % (sizeBits, lVal, rVal),
        flags=[
            ["z", "SET_ZF(%s)" % (sizeBits)],
            ["a", "SET_AF_DEC(%s)" % (sizeBits)],
            [
                "o",
                "SET_OF_INC_DEC_NEG(%s, %s)" % (
                    sizeBits, hex(ofMask[sizeBytes] - 1)),
            ],
        ],
        actions=["%s = tmp%s" % (lVal, sizeBits)],
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def cdqe(inst, cg):
    cg.add_log("// cdqe not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def cmp(left, right, inst, cg):
    # cmp is sub without setting value
    sub(left, right, inst, cg, True)


def jmp(op, inst, cg):
    cg.add_log(f"goto _{hex(int(op.value))}", comment=(
        f"{inst.mnemonic}\t{inst.op_str};"))


def jne(op, inst, cg):
    cg.add_log(
        f"if(!zf)\n        goto _{hex(int(op.value))}",
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def je(op, inst, cg):
    cg.add_log(
        f"if(zf)\n         goto _{hex(int(op.value))}",
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def jb(op, inst, cg):
    cg.add_log(
        f"if(cf)\n         goto _{hex(int(op.value))};",
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def jbe(op, inst, cg):
    cg.add_log(
        f"if(cf == 1 || zf == 1)\n      goto _{hex(int(op.value))}",
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def jnb(op, inst, cg):
    cg.add_log(
        f"if(!cf)\n        goto _{hex(int(op.value))}",
        comment=(f"{inst.mnemonic}\t{inst.op_str};"),
    )


def enter(left, right, inst, cg):
    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def and_(left, right, inst, cg):
    # append postfix expression
    if left.value == 'al' and right.value == 'cl':
        cg.rung.append('and')

    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def push(op, inst, cg):
    payload = f"{inst.mnemonic}\t{inst.op_str};"
    if op.type == X86_OP_IMM and op.value == '0':
        payload = payload + '\n\n'
    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=payload)


def pop(op, inst, cg):
    payload = f"{inst.mnemonic}\t{inst.op_str};"
    cg.add_log(f"// {inst.mnemonic} not implemented yet", comment=payload)


def or_(left, right, inst, cg):
    # append postfix expression
    if left.value == 'al' and right.value == 'cl':
        cg.rung.append('or')

    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def xor(left, right, inst, cg):
    # append postfix expression
    if left.value == 'al' and right.value == 'cl':
        cg.rung.append('xor')

    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def shr(left, right, inst, cg):
    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def rcl(left, right, inst, cg):
    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def call(op, inst, cg):
    payload = f"{inst.mnemonic}\t{inst.op_str};"

    # mark a PLC instruction
    if op.type == X86_OP_REG and op.value == 'ebx':
        payload += f" someone PLC instruction will be use."

    cg.add_log(f" ", comment=payload)


def not_(op, inst, cg):
    payload = f"{inst.mnemonic}\t{inst.op_str};"

    # handle eax
    if op.type == X86_OP_REG and op.value == 'eax':
        cg.regs['eax'].set_value_u32(cg.regs['eax'].value)
        payload += f" eax is {cg.regs['eax'].value}"

        # identify not Logic gate
        if cg.not_flag:
            cg.rung.append('not')

    cg.add_log(" ", comment=payload)

def test(left, right, inst, cg):

    # # avoid EN disturb identifying `not` logic gate
    # if left.value == 'eax' and right.value == 'eax' and cg.not_flag:
    #     if cg.rung[-1] == 'not':
    #         cg.rung.pop()

    cg.add_log(f"// {inst.mnemonic} not implemented yet",
               comment=(f"{inst.mnemonic}\t{inst.op_str};"))


def leave(op, inst):
    pass


def ret(op, inst):
    pass

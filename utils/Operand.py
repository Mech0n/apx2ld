from rich.console import Console

from .Register import regsScale, regsSize
from .x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


class Operand:
    def __init__(self, type, value, size):
        self.type = type
        self.value = value
        self.sizeBytes = size
        self.sizeBits = size * 8

    def getAsMemoryRef(self, size=0):
        if size != 0:
            dataType = regsScale[size]
        else:
            dataType = regsScale[self.sizeBytes]

        # Type other than MEM, so this will propably not compile
        if self.type != X86_OP_MEM:
            return "_no_no_no_"

        return "MEMORY(%s, %s)" % (dataType, self.value)

    def getAsRegImm(self, size=0):
        if not size:
            size = self.sizeBytes
        for r in regsSize:
            if self.value in r[0]:
                return r[1][size]

        # Propably imm
        return self.value

    def getValue(self, size=0):
        try:
            if self.type == X86_OP_MEM:
                return self.getAsMemoryRef(size)
            elif self.type == X86_OP_IMM or self.type == X86_OP_REG:
                return self.getAsRegImm(size)

            raise Exception("!!!")
        except Exception as e:
            with Console() as c:
                c.print(f"[Module] Operand [Method] getValue: {e}")

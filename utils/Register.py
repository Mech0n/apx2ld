regsSize = [
    [["rax", "eax", "ax", "al", "ah"], {1: "al", 2: "ax", 4: "eax", 8: "rbx"}],
    [["rbx", "ebx", "bx", "bl", "bh"], {1: "bl", 2: "bx", 4: "ebx", 8: "rbx"}],
    [["rcx", "ecx", "cx", "cl", "ch"], {1: "cl", 2: "cx", 4: "ecx", 8: "rcx"}],
    [["rdx", "edx", "dx", "dl", "dh"], {1: "dl", 2: "dx", 4: "edx", 8: "rdx"}],
]

regsScale = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}

regMask = {1: 0xff, 2: 0xffff, 4: 0xffffffff, 8: 0xffffffffffffffff}

class register(object) :
    def __init__(self, type) -> None:
        # reg type
        self.type = type    
        self.value = 0

    def set_value_u8(self, value: int) -> None:
        self.value = (self.value & (0xffffffffffffffff - 0xff)) + (value & 0xff)

    def set_value_u16(self, value: int) -> None:
        self.value = (self.value & (0xffffffffffffffff - 0xffff)) + (value & 0xffff)

    def set_value_u32(self, value: int) -> None:
        self.value = (self.value & (0xffffffffffffffff - 0xffffffff)) + (value & 0xffffffff)

    def set_value_u64(self, value: int) -> None:
        self.value = (value & 0xffffffffffffffff)
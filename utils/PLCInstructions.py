"""
    variable:
    - output flag
    - value
    - disp
    - '+'
"""

class Variable (object):
    def __init__(self, disp: int, output_flag=False, input_flag=False, value=0) -> None:
        self.disp = disp    # tag
        self.output_flag = output_flag
        self.input_flag = input_flag
        self.value = value

    def setOutputFlag(self, flag):
        self.output_flag = flag

    def setInputFlag(self, flag):
        self.input_flag = flag

    def setValue(self, value):
        self.value = value

"""
    func:
    - disp: "mov bx, 0xbalabala"
    - input_list: [ only disp ]
    - output_list: [ only disp ]
    - time
"""
class FBD (object):
    def __init__(self) -> None:
        self.input_list = set()
        self.output_list = set()
        self.disp = 0
        self.time = -1
    
    def insert_input_list(self, variable_disp:int) -> None: 
        self.input_list.add(variable_disp)

    def insert_output_list(self, variable_disp:int) -> None: 
        self.output_list.add(variable_disp)

    def set_disp(self, disp: int) -> None:
        self.disp = disp
    
    def set_time(self, time: int) -> None:
        self.time = time


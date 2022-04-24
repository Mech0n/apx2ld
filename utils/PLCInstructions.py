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
    - disp
    - '*'
"""

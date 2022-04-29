from re import finditer, search
from zlib import decompress


class apx(object):
    def __init__(self, filename) -> None:
        self.filename = filename
        
        """
            start : end #[start:end]
        """
        self.pkzip_files = {}

        # target PLC code
        self.code = b""
        
        # only use when the file write by ST
        self.source = b""

        # locate data
        self.data_locate : None | tuple = None

    def load_file(self, start, stop):
        with open(self.filename, "rb") as f:
            code = f.read()
            return code[start:stop]

    def load_file_all(self):
        with open(self.filename, "rb") as f:
            code = f.read()
            return code

    def extract_pkfile(self) -> None:
        if len(self.pkzip_files) != 0:
            # TODO: warning msg
            return
        magic = b"PK\001\002"
        data = self.load_file_all()
        anchor_points = []

        for m in finditer(magic, data):
            anchor_points.append(m.start())
        anchor_points.append(len(data))

        for idx in range(len(anchor_points) - 1):
            self.pkzip_files[anchor_points[idx]] = anchor_points[idx + 1]
        
    def extract_code(self) -> bool:
        code_start_magic = b'\xC8..\x00'
        code_end_magic = b'\xC9[\xC3\xC2]'

        # print(len(self.pkzip_files))
        if len(self.pkzip_files) == 0:
            self.extract_pkfile()
        
        for key, value in self.pkzip_files.items():
            data = self.load_file(key, value)
            code_start = search(code_start_magic, data)
            code_end = (search(code_end_magic, data))

            if code_start and code_end:
                self.code = self.load_file(key + code_start.span()[0], key + code_end.span()[1])
                # locate data
                self.data_locate = (key, value)
                return True
        return False

    def extract_LDExchangeFile(self) -> list | None:
        if self.data_locate == None:
            # TODO: Error msg
            return 

        zlib_magic = b'\x78[\xDA\x9C]'
        data = self.load_file(self.data_locate[0], self.data_locate[1])
        zlib_file = search(zlib_magic, data)

        # No zlibc file in it
        if zlib_file == None:
            # TODO: Error msg
            return 

        zlib_file_start = zlib_file.span()[0]

        origin_data = decompress(data[zlib_file_start:])
        xml_header = b'<\\?xml version="1\\.0" encoding="UTF-8" standalone="yes"\\?>'
        target_data = search(xml_header, origin_data)

        if target_data == None:
            # TODO: Error msg
            return
        
        target_data_start = target_data.span()[0]
        # return origin_data[target_data_start+55:]

        LD_variable = []
        cursor = target_data_start + 55
        while cursor < len(origin_data):
            tmp = origin_data[cursor + 1: cursor + origin_data[cursor] + 1]
            LD_variable.append(tmp)
            cursor = cursor + origin_data[cursor] + 1
        
        return LD_variable


if __name__ == "__main__":
    a = apx("../Station.apx")
    a.extract_pkfile()
    # print(a.pkzip_files)
    if a.extract_code():
        print(a.code)
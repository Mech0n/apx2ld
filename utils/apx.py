from re import finditer, search

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
                return True
        return False


if __name__ == "__main__":
    a = apx("../Station.apx")
    a.extract_pkfile()
    # print(a.pkzip_files)
    if a.extract_code():
        print(a.code)
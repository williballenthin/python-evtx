import binascii



class FileHeader(Block):
    def __init__(self, buf, offset, parent):
        debug("FILE HEADER at %s." % (hex(offset))))
        super(FileHeader, self).__init__(buf, offset, parent)
        self.declare_field("string", "magic", 0x0, 8)
        self.declare_field("qword",  "unused")
        self.declare_field("qword",  "current_chunk_number")
        self.declare_field("qword",  "next_record_number")
        self.declare_field("dword",  "header_size")
        self.declare_field("word",   "minor_version")
        self.declare_field("word",   "major_version")
        self.declare_field("word",   "header_chunk_size")
        self.declare_field("word",   "chunk_count")
        self.declare_field("dword",  "flags")
        self.declare_field("dword",  "checksum")

    def check_magic(self):
        return self.magic() == "ElfFile\x00"

    def verify(self):
        return self.check_magic() and \
            self.major_version() == 0x3 and \
            self.minor_version() == 0x1 and \
            self.header_chunk_size == 0x1000 and \
            self.checksum() == (binascii.crc32(self._buf[0:0x78]) & 0xFFFFFFFF)
    

    def is_dirty(self):
        return self.flags() & 0x1
              
    def is_full(self):
        return self.flags() & 0x2

class ChunkHeader(Block):
    def __init__(self, buf, offset, parent):
        debug("CHUNK HEADER at %s." % (hex(offset)))
        super(ChunkHeader, self).__init__(buf, offset, parent)
        self.declare_field("string", "magic", 0x0, 8)
        self.declare_field("qword", "log_first_record_number")
        self.declare_field("qword", "log_last_record_number")
        self.declare_field("qword", "file_first_record_number")
        self.declare_field("qword", "file_last_record_number")
        self.declare_field("word", "header_size")
        self.declare_field("word", "first_record_offset")
        self.declare_field("word", "last_record_offset")
        self.declare_field("binary", "unused", 0x4c)
        self.declare_field("dword",  "checksum")

    def check_magic(self):
        return self.magic() == "ElfChnk\x00"


#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.0.1

import binascii
import mmap
import contextlib
from exceptions import NotImplementedError

from BinaryParser import *
from Nodes import *


class InvalidRecordException(ParseException):
    def __init__(self):
        super(InvalidRecordException, self).__init__("Invalid record structure")


class FileHeader(Block):
    def __init__(self, buf, offset):
        debug("FILE HEADER at %s." % (hex(offset)))
        super(FileHeader, self).__init__(buf, offset)
        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword",  "oldest_chunk")
        self.declare_field("qword",  "current_chunk_number")
        self.declare_field("qword",  "next_record_number")
        self.declare_field("dword",  "header_size")
        self.declare_field("word",   "minor_version")
        self.declare_field("word",   "major_version")
        self.declare_field("word",   "header_chunk_size")
        self.declare_field("word",   "chunk_count")
        self.declare_field("binary", "unused1", length=0x4c)
        self.declare_field("dword",  "flags")
        self.declare_field("dword",  "checksum")

    def __repr__(self):
        return "FileHeader(buf=%r, offset=%r)" % (self._buf, self._offset)

    def __str__(self):
        return "FileHeader(offset=%s)" % (hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the FileHeader match the expected magic value.
        """
        return self.magic() == "ElfFile\x00"

    def calculate_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum off the first 0x78 bytes.
          This is consistent with the checksum stored by the FileHeader.
        """
        return binascii.crc32(self.unpack_binary(0, 0x78)) & 0xFFFFFFFF

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader 
          successfully passes a set of heuristic checks that
          all EVTX FileHeaders should pass.
        """
        return self.check_magic() and \
            self.major_version() == 0x3 and \
            self.minor_version() == 0x1 and \
            self.header_chunk_size() == 0x1000 and \
            self.checksum() == self.calculate_checksum()

    def is_dirty(self):
        """
        @return A boolean that indicates that the log has been
          opened and was changed, though not all changes might be
          reflected in the file header.
        """
        return self.flags() & 0x1 == 0x1
              
    def is_full(self):
        """
        @return A boolean that indicates that the log
          has reached its maximum configured size and the retention
          policy in effect does not allow to reclaim a suitable amount
          of space from the oldest records and an event message could
          not be written to the log file.
        """
        return self.flags() & 0x2

    def first_chunk(self):
        """
        @return A ChunkHeader instance that is the first chunk
          in the log file, which is always found directly after
          the FileHeader.
        """
        ofs = self._offset + self.header_chunk_size()
        return ChunkHeader(self._buf, ofs)

    def current_chunk(self):
        """
        @return A ChunkHeader instance that is the current chunk
          indicated by the FileHeader.
        """
        ofs = self._offset + self.header_chunk_size()
        ofs += (self.current_chunk_number() * 0x10000)
        return ChunkHeader(self._buf, ofs)

    def chunks(self):
        """
        @return A generator that yields the chunks of the log file
          starting with the first chunk, which is always found directly
          after the FileHeader, and continuing to the end of the file.
        """
        ofs = self._offset + self.header_chunk_size()
        while ofs + 0x10000 < len(self._buf):
            yield ChunkHeader(self._buf, ofs)
            ofs += 0x10000


class ChunkHeader(Block):
    def __init__(self, buf, offset):
        debug("CHUNK HEADER at %s." % (hex(offset)))
        super(ChunkHeader, self).__init__(buf, offset)
        self._strings = None
        self._templates = None

        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword",  "file_first_record_number")
        self.declare_field("qword",  "file_last_record_number")
        self.declare_field("qword",  "log_first_record_number")
        self.declare_field("qword",  "log_last_record_number")
        self.declare_field("dword",  "header_size")
        self.declare_field("dword",  "last_record_offset")
        self.declare_field("dword",  "next_record_offset")
        self.declare_field("dword",  "data_checksum")
        self.declare_field("binary", "unused", length=0x44)
        self.declare_field("dword",  "header_checksum")

    def __repr__(self):
        return "ChunkHeader(buf=%r, offset=%r)" % (self._buf, self._offset)

    def __str__(self):
        return "ChunkHeader(offset=%s)" % (hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the ChunkHeader match the expected magic value.
        """
        return self.magic() == "ElfChnk\x00"

    def calculate_header_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the ChunkHeader fields.
        """
        data = self.unpack_binary(0x0, 0x78)
        data += self.unpack_binary(0x80, 0x180)
        return binascii.crc32(data) & 0xFFFFFFFF

    def calculate_data_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the Chunk data.
        """
        data = self.unpack_binary(0x200, self.next_record_offset() - 0x200)
        return binascii.crc32(data) & 0xFFFFFFFF

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader 
          successfully passes a set of heuristic checks that
          all EVTX ChunkHeaders should pass.
        """
        return self.check_magic() and \
            self.calculate_header_checksum() == self.header_checksum() and \
            self.calculate_data_checksum() == self.data_checksum()

    def _load_strings(self):
        if self._strings is None:
            self._strings = {}
        for i in xrange(64):
            ofs = self.unpack_dword(0x80 + (i * 4))
            while ofs > 0:
                string_node = self.add_string(ofs)
                ofs = string_node.next_offset()

    def strings(self):
        """
        @return A dict(offset --> NameStringNode)
        """
        if not self._strings:
            self._load_strings()
        return self._strings

    def add_string(self, offset, parent=None):
        """
        @param offset An integer offset that is relative to the start of
          this chunk.
        @param parent (Optional) The parent of the newly created 
           NameStringNode instance. (Default: this chunk).
        @return None
        """
        if self._strings is None:
            self._load_strings()
        string_node = NameStringNode(self._buf, self._offset + offset, 
                                     self, parent or self)
        self._strings[offset] = string_node
        return string_node

    def _load_templates(self):
        """
        @return None
        """
        if self._templates is None:
            self._templates = {}
        for i in xrange(32):
            ofs = self.unpack_dword(0x180 + (i * 4))
            while ofs > 0:
                # unclear why these are found before the offset
                # this is a direct port from A.S.'s code
                token   = self.unpack_byte(ofs - 10)
                pointer = self.unpack_dword(ofs - 4)
                if token != 0x0c or pointer != ofs:
                    warning("Unexpected token encountered")
                    ofs = 0
                    continue
                template = self.add_template(ofs)
                ofs = template.next_offset()

    def add_template(self, offset, parent=None):
        """
        @param offset An integer which contains the chunk-relative offset
           to a template to load into this Chunk.
        @param parent (Optional) The parent of the newly created 
           TemplateNode instance. (Default: this chunk).
        @return Newly added TemplateNode instance.
        """
        if self._templates is None:
            self._load_templates()
            
        template = TemplateNode(self._buf, self._offset + offset, 
                                self, parent or self)
        self._templates[offset] = template
        return template

    def templates(self):
        """
        @return A dict(offset --> TemplateNode) of all encountered 
          templates in this Chunk.
        """
        if not self._templates:
            self._load_templates()
        return self._templates

    def first_record(self):
        return Record(self._buf, self._offset + 0x200, self)

    def records(self):
        record = self.first_record()
        while record._offset < self._offset + self.next_record_offset():
            yield record
            try:
                record = Record(self._buf, 
                                record._offset + record.length(), 
                                self)
            except InvalidRecordException:
                return


class Record(Block):
    def __init__(self, buf, offset, chunk):
        debug("Record at %s." % (hex(offset)))
        super(Record, self).__init__(buf, offset)
        self._chunk = chunk
        
        self.declare_field("dword", "magic", 0x0)  # 0x00002a2a
        self.declare_field("dword", "size")
        self.declare_field("qword", "record_num")
        self.declare_field("filetime", "timestamp")

        if self.size() > 0x10000:
            raise InvalidRecordException()

        self.declare_field("dword", "size2", self.size() - 4)

    def root(self):
        return RootNode(self._buf, self._offset + 0x18, self._chunk, self)

    def length(self):
        return self.size()

    def verify(self):
        return self.size() == self.size2()
                                         

def main():
    import sys    
    import BinaryParser


    with open(sys.argv[1], 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, 
                                          access=mmap.ACCESS_READ)) as buf:

            fh = FileHeader(buf, 0x0)
            print fh.verify()
            
            # for ch in fh.chunks():
            #     print ch.verify()
            #     if ch.verify():
            #         print "----- strings ------"
            #         for s in ch.strings().values():
            #             print xml(s)
            #         print "----- templates ------"
            #         for s in ch.templates().values():
            #             print xml(s)
            ch = fh.first_chunk()
            ch._load_strings()
            ch._load_templates()

            BinaryParser.verbose = True
#            t = ch.templates()[0x1c07]
#            t = ch.templates()[0x0814]
#            t = ch.templates()[0x0b7f]
#            t = ch.templates()[0x1027]
            t = ch.templates()[0x0226]

            print "(((((((((())))))))))"


            items = []
            def printer(n, indent=""):
                out = "..%s %s" % (indent, str(n))
                print out

                items.append(n)
                for c in n.children():
                    printer(c, indent + "  ")
            printer(t)

            print "*******************"
            for item in items:
                print str(item)
                print hex_dump(item._buf[item._offset:item._offset + item.length()], start_addr=item._offset)
                print "\n\n"

            print xml(t)
            

if __name__ == "__main__":
    main()


#!/bin/python
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
#   Version v0.1.1


import sys
import binascii
import mmap
import contextlib
from Evtx.Evtx import FileHeader


def main():
    with open(sys.argv[1], 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, 
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            print "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>"
            print "<Events>"
            for chunk in fh.chunks():
                for record in chunk.records():
                    print record.root().xml([]).encode("utf-8")
            print "</Events>"            

if __name__ == "__main__":
    main()


#!/usr/bin/env python3
"""
    This file is part of python-evtx.

    Copyright 2012, 2013
        Willi Ballenthin <william.ballenthin@mandiant.com>
        while at Mandiant <http://www.mandiant.com>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""
import mmap
import contextlib
import lxml.etree as etree

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view


def main():
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description="Dump a binary EVTX file into XML."
    )
    parser.add_argument(
        "--cleanup"
      , action="store_true"
      , help="Cleanup unused XML entities (slower)"
    )
    parser.add_argument(
        "evtx"
      , type=str
      , help="Path to the Windows EVTX event log file"
    )
    args = parser.parse_args()
    with open(args.evtx, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            xml  = etree.fromstring(
                ''.join(
                    [ '<Events>', ]
                  + [ elem.decode("utf8") for elem, _ in evtx_file_xml_view(fh) ]
                  + [ '</Events>', ]
                )
            )
            xml = etree.tostring(xml, pretty_print=True, encoding='utf-8', xml_declaration=True, standalone=True)
            xml = xml.decode('utf-8')
            print(xml)

if __name__ == "__main__":
    main()

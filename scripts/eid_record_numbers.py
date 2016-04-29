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
from lxml.etree import XMLSyntaxError
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

from filter_records import get_child
from filter_records import to_lxml


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Print the record numbers of EVTX log entries "
                    "that match the given EID.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("eid", type=int,
                        help="The EID of records to extract")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                node = to_lxml(xml)
            except XMLSyntaxError:
                continue
            if args.eid != int(get_child(get_child(node, "System"), "EventID").text):
                continue
            print record.record_num()


if __name__ == "__main__":
    main()

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
from lxml import etree
#import xml.etree.cElementTree as etree

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view


def to_lxml(record_xml):
    """
    @type record: Record
    """
    return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
                         record_xml)


def xml_records(filename):
    """
    If the second return value is not None, then it is an
      Exception encountered during parsing.  The first return value
      will be the XML string.

    @type filename str
    @rtype: generator of (etree.Element or str), (None or Exception)
    """
    with Evtx(filename) as evtx:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield to_lxml(xml), None
            except etree.XMLSyntaxError as e:
                yield xml, e


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    """
    @type node: etree.Element
    @type tag: str
    @type ns: str
    """
    return node.find("%s%s" % (ns, tag))


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Print only entries from an EVTX file with a given EID.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("eid", type=int,
                        help="The EID of records to print")

    args = parser.parse_args()

    for node, err in xml_records(args.evtx):
        if err is not None:
            continue
        sys = get_child(node, "System")
        if args.eid == int(get_child(sys, "EventID").text):
            print etree.tostring(node, pretty_print=True)


if __name__ == "__main__":
    main()

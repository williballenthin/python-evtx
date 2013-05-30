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
import mmap
import contextlib

import argparse

from Evtx.Nodes import RootNode
from Evtx.Evtx import FileHeader
from Evtx.Evtx import make_template_xml_view


def build_record_xml(record, cache=None):
    if cache is None:
        cache = {}

    def rec(root_node):
        f = make_template_xml_view(root_node, cache=cache)
        subs_strs = []
        for sub in root_node.fast_substitutions():
            if isinstance(sub, basestring):
                subs_strs.append(sub.encode("ascii", "xmlcharrefreplace"))
            elif isinstance(sub, RootNode):
                subs_strs.append(rec(sub))
            else:
                subs_strs.append(str(sub))
        return f.format(*subs_strs)
    return rec(record.root())


def main():
    parser = argparse.ArgumentParser(
        description="Doing some work.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    with open(args.evtx, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            for chunk in fh.chunks():
                cache = {}
                for record in chunk.records():
                    record_str = build_record_xml(record, cache=cache)
                    print record_str.encode("ascii", "xmlcharrefreplace")


if __name__ == "__main__":
    main()

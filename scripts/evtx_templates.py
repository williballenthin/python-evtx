#!/usr/bin/env python
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
#   Version v0.1
import Evtx.Evtx as evtx
import Evtx.Views as e_views


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump templates from a binary EVTX file.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:
        for i, chunk in enumerate(log.chunks()):
            for template in list(chunk.templates().values()):
                print("Template {%s} at chunk %d, offset %s" %
                      (template.guid(), i,
                       hex(template.absolute_offset(0x0))))
                print(e_views.evtx_template_readable_view(template))


if __name__ == "__main__":
    main()

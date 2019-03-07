#!/usr/bin/env python


import Evtx.Evtx as evtx
import Evtx.Views as e_views


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Print the structure of an EVTX record's template.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int,
                        help="Record number")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:
        r = log.get_record(args.record)
        if r is None:
            print("error: record not found")
            return -1
        else:
            print(e_views.evtx_template_readable_view(r.root()))


if __name__ == "__main__":
    main()

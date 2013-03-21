import sys

from Evtx.Evtx import Evtx


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Parse the EVTX log entries from an file that match the given EID.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int,
                        help="The record number of the record to extract")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        record = evtx.get_record(args.record)
        if record is None:
            raise RuntimeError("Cannot find the record specified.")
        sys.stdout.write(record.data())


if __name__ == "__main__":
    main()
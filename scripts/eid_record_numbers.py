from Evtx.Evtx import Evtx

from filter_records import get_child
from filter_records import to_lxml


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Print the record numbers of EVTX log entries that match the given EID.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("eid", type=int,
                        help="The EID of records to extract")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        for record in evtx.records():
            node = to_lxml(record)
            if args.eid != int(get_child(get_child(node, "System"), "EventID").text):
                continue
            print record.record_num()


if __name__ == "__main__":
    main()
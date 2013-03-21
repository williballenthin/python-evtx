from lxml import etree

from Evtx.Evtx import Evtx


def to_lxml(record):
    """
    @type record: Record
    """
    return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
                            (record.root().xml([]).encode("utf-8")))


def xml_records(filename):
    """
    @type filename str
    """
    with Evtx(filename) as evtx:
        for record in evtx.records():
            yield(to_lxml(record))


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    """
    @type node: Element
    @type tag: str
    @type ns: str
    """
    return node.find("%s%s" % (ns, tag))


def eid_filter(records, eid):
    """
    @type records: generator of Element
    """
    for record in records:
        sys = get_child(record, "System")
        if eid == int(get_child(sys, "EventID").text):
            yield record


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Print only entries from an EVTX file with a given EID.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("eid", type=int,
                        help="The EID of records to print")

    args = parser.parse_args()

    for record in eid_filter(xml_records(args.evtx), args.eid):
        print etree.tostring(record, pretty_print=True)


if __name__ == "__main__":
    main()

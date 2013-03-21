from Evtx.Evtx import Evtx
from Evtx.Nodes import RootNode


def describe_record(record, indent=0, suppress_values=False):
    """
    @type record: Record
    @type indent: int
    @rtype None
    """
    def format_node(n):
        """
        Depends on closure over `record`.
        @type n: BXmlNode
        @rtype str
        """
        return "%s(offset=%s)" % \
               (n.__class__.__name__, hex(n.offset() - record.offset()))

    def rec(node, indent=0):
        """
        @type node: BXmlNode
        @type indent: int
        @rtype str
        """
        ret = ""
        ret += "%s%s\n" % ("  " * indent, format_node(node))
        for child in node.children():
            ret += rec(child, indent=indent + 1)
        if isinstance(node, RootNode):
            ret += "%sSubstitutions\n" % ("  " * (indent + 1))
            for sub in node.substitutions():
                if suppress_values:
                    ret += "%s%s\n" % ("  " * (indent + 2), format_node(sub))
                else:
                    ret += "%s%s --> %s\n" % ("  " * (indent + 2), format_node(sub), sub.string())
        return ret

    ret = ""
    ret += "%srecord(absolute_offset=%s)" % ("  " * (indent), record.offset())
    ret += rec(record.root(), indent=indent + 1)
    return ret


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Pretty print the binary structure of an EVTX record.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int,
                        help="Record number")
    parser.add_argument("--suppress_values", action="store_true",
                        help="Do not print the values of substitutions.")
    args = parser.parse_args()

    with Evtx(args.evtx) as evtx:
        print describe_record(evtx.get_record(args.record), suppress_values=args.suppress_values)


if __name__ == "__main__":
    main()

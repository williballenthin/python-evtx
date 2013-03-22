from Evtx.Evtx import Evtx
from Evtx.Nodes import RootNode
from Evtx.Nodes import TemplateInstanceNode
from Evtx.Nodes import VariantTypeNode
from Evtx.BinaryParser import hex_dump


def describe_record(record, indent=0, suppress_values=False):
    """
    @type record: Record
    @type indent: int
    @rtype: None
    """
    def format_node(n, extra=None):
        """
        Depends on closure over `record` and `suppress_values`.
        @type n: BXmlNode
        @type extra: str
        @rtype: str
        """
        ret = ""
        if extra is not None:
            ret = "%s(offset=%s, %s)" % \
                   (n.__class__.__name__, hex(n.offset() - record.offset()), extra)
        else:
            ret = "%s(offset=%s)" % \
                   (n.__class__.__name__, hex(n.offset() - record.offset()))

        if not suppress_values and isinstance(n, VariantTypeNode):
            ret += " --> %s" % (n.string())
        return ret

    def rec(node, indent=0):
        """
        @type node: BXmlNode
        @type indent: int
        @rtype: str
        """
        ret = ""
        if isinstance(node, TemplateInstanceNode):
            if node.is_resident_template():
                ret += "%s%s\n" % ("  " * indent, format_node(node, extra="resident=True, length=%s" % (hex(node.template().data_length()))))
                ret += rec(node.template(), indent=indent + 1)
            else:
                ret += "%s%s\n" % ("  " * indent, format_node(node, extra="resident=False"))
        else:
            ret += "%s%s\n" % ("  " * indent, format_node(node))

        for child in node.children():
            ret += rec(child, indent=indent + 1)
        if isinstance(node, RootNode):
            ofs = node.tag_and_children_length()
            ret += "%sSubstitutions(offset=%s)\n" % ("  " * (indent + 1), hex(node.offset() - record.offset() + ofs))
            for sub in node.substitutions():
                ret += "%s%s\n" % ("  " * (indent + 2), format_node(sub))
        return ret

    ret = ""
    ret += "%srecord(absolute_offset=%s)\n" % ("  " * (indent), record.offset())
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
        print hex_dump(evtx.get_record(args.record).data())
        print describe_record(evtx.get_record(args.record), suppress_values=args.suppress_values)


if __name__ == "__main__":
    main()

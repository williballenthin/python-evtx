#!/usr/bin/env python
import hexdump

import Evtx.Evtx as evtx
from Evtx.Nodes import RootNode
from Evtx.Nodes import BXmlTypeNode
from Evtx.Nodes import TemplateInstanceNode
from Evtx.Nodes import VariantTypeNode


def describe_root(record, root, indent=0, suppress_values=False):
    """
    Args:
      record (Evtx.Record):
      indent (int):
    """
    def format_node(n, extra=None, indent=0):
        """
        Depends on closure over `record` and `suppress_values`.

        Args:
          n (Evtx.Nodes.BXmlNode):
          extra (str):

        Returns:
          str:
        """
        ret = ""
        indent_s = '  ' * indent
        name = n.__class__.__name__
        offset = n.offset() - record.offset()
        if extra is not None:
            ret = "%s%s(offset=%s, %s)" % (indent_s, name, hex(offset), extra)
        else:
            ret = "%s%s(offset=%s)" % (indent_s, name, hex(offset))

        if not suppress_values and isinstance(n, VariantTypeNode):
            ret += " --> %s" % (n.string())
            if isinstance(n, BXmlTypeNode):
                ret += "\n"
                ret += describe_root(record, n._root, indent=indent + 1)

        return ret

    def rec(node, indent=0):
        """
        Args:
          node (Evtx.Nodes.BXmlNode):
          indent (int):

        Returns:
          str:
        """
        ret = ""
        if isinstance(node, TemplateInstanceNode):
            if node.is_resident_template():
                extra = "resident=True, length=%s" % (hex(node.template().data_length()))
                ret += "%s\n" % (format_node(node, extra=extra, indent=indent))
                ret += rec(node.template(), indent=indent + 1)
            else:
                ret += "%s\n" % (format_node(node, extra="resident=False", indent=indent))
        else:
            ret += "%s\n" % (format_node(node, indent=indent))

        for child in node.children():
            ret += rec(child, indent=indent + 1)

        if isinstance(node, RootNode):
            ofs = node.tag_and_children_length()
            indent_s = '  ' * (indent + 1)
            offset = node.offset() - record.offset() + ofs
            ret += "%sSubstitutions(offset=%s)\n" % (indent_s, hex(offset))
            for sub in node.substitutions():
                ret += "%s\n" % (format_node(sub, indent=indent + 2))

        return ret

    ret = ""
    ret += rec(root, indent=indent)
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

    with evtx.Evtx(args.evtx) as log:
        hexdump.hexdump(log.get_record(args.record).data())

        record = log.get_record(args.record)
        print("record(absolute_offset=%s)" % record.offset())
        print(describe_root(record, record.root(), suppress_values=args.suppress_values))
        print(record.xml())


if __name__ == "__main__":
    main()

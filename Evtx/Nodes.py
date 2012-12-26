from BinaryParser import *


def xml(item):
    return item.__xml__()


indent = ""


class BXmlNode(Block):
    def __init__(self, buf, offset, chunk, parent):
        debug("BXmlNode at %s." % (hex(offset)))
        super(BXmlNode, self).__init__(buf, offset)
        self._chunk = chunk
        self._parent = parent
        self._dispatch_table = [
            Node0x00,
            OpenStartElementNode,
            CloseStartElementNode,
            Node0x03,
            CloseElementNode,
            ValueNode,
            AttributeNode,
            Node0x07,
            Node0x08,
            Node0x09,
            Node0x0A,
            Node0x0B,
            Node0x0C,
            NormalSubstitutionNode,
            Node0x0E,
            StreamStartNode,
            ]
        self._readable_tokens = [
            "EndItem",
            "Open Start Element",
            "Close Start Element",
            "unknown",
            "Close Element",
            "Value",
            "Attribute",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "Normal Substition",
            "unknown",
            "Start of Stream",            
            ]


    def __repr__(self):
        return "BXmlNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "BXmlNode(offset=%s)" % (hex(self._offset))

    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for %r") % (self)

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        """
        This method must be implemented and overridden for all BXmlNodes.
        @return An integer specifying the length of this tag, not including
          its children.
        """
        raise NotImplementedError("tag_length not implemented for %r") % \
            (self)

    def verify(self):
        return true

    #@memoize
    def children(self):
        """
        @return A list containing all of the children BXmlNodes.
        """
        ret = []
        ofs = self.tag_length()

        global indent
        print indent, self, "children"

        indent += "\t"

        while True:
            # we lose error checking by masking off the higher nibble,
            #   but, some tokens like 0x01, make use of the flags nibble.
            token = self.unpack_byte(ofs) & 0x0F
            print indent, "token", hex(token), \
                "(%s)" % self._readable_tokens[token], \
                "@", hex(self._offset + ofs)
            if token == 0x00:
                break
            try:
                HandlerNodeClass = self._dispatch_table[token]
                child = HandlerNodeClass(self._buf, self._offset + ofs, 
                                         self._chunk, self)
            except IndexError:
                raise ParseException("Unexpected token %02X at %s" % \
                                         (token, 
                                          self.absolute_offset(0x0) + ofs))
            ret.append(child)
            ofs += child.length()

        indent = indent[:-2]

        return ret

    #@memoize
    def length(self):
        """
        @return An integer specifying the length of this tag and all
          its children.
        """
        ret = self.tag_length()
        for child in self.children():
            ret += child.length()
        ret += 1  # for the 0x00 token
        return ret


class NameStringNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        debug("NameStringNode at %s." % (hex(offset)))
        super(NameStringNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("word", "hash")
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "string", length=self.string_length())

    def __repr__(self):
        return "NameStringNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "NameStringNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        return self.string()
    
    def tag_length(self):
        return (self.string_length() * 2) + 8


class TemplateNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        debug("TemplateNode at %s." % (hex(offset)))
        super(TemplateNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("dword", "template_id")
        self.declare_field("guid",  "guid", 0x04) # unsure why this overlaps
        self.declare_field("dword", "data_length")

    def __repr__(self):
        return "TemplateNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "TemplateNode(offset=%s, guid=%s)" % \
            (hex(self._offset), self.guid())
    
    def __xml__(self):
        # TODO(wb): this.
        cxml = "".join(xml(c) for c in self.children())
        return "<<template %s>>\n%s<</template %s>>" % (self.guid(), 
                                                        cxml,
                                                        self.guid())
        return self.guid()
    
    def tag_length(self):
        return 24

    def length(self):
        return self.tag_length() + self.data_length()

class Node0x00(BXmlNode):
    """
    The binary XML node for the system token 0x00.

    This is the "end of stream" token. It may never actually
      be instantiated here.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x00 at %s." % (hex(offset)))
        super(Node0x00, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x00(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x00(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x00")
    
    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []

class OpenStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x01.

    This is the "open start element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("OpenStartElementNode at %s." % (hex(offset)))
        super(OpenStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "unknown0")
        self.declare_field("dword", "size")
        self.declare_field("dword", "string_offset")
        self._tag_length = 11
        self._element_type = 0

        if self.flags() & 0x04:
            self._tag_length += 4
            debug("Has extra four, total length %s" % (self._tag_length))

        global indent

        if self.string_offset() > self._offset - self._chunk._offset:
            print indent, "%r" % (self), "need new string", self.string_offset()
            string_node = NameStringNode(self._buf, 
                                         self._chunk._offset + self.string_offset(),
                                         self._chunk,
                                         self._chunk)
            self._chunk.add_string(self.string_offset(), string_node)
            self._tag_length += string_node.tag_length()

        print indent, "Start Element", self, "tag length", self.tag_length()

    def __repr__(self):
        return "OpenStartElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "OpenStartElementNode(offset=%s, name=%s)" % \
            (hex(self._offset), self.tag_name())
    
    def __xml__(self):
        if len(self.children()) == 0:
            return "\n<%s />" % (self.tag_name())
        else:
            cxml = "".join(xml(c) for c in self.children())
            return "\n<%s %s</%s>" % (self.tag_name(), cxml, self.tag_name())

    def tag_name(self):
        return xml(self._chunk.strings()[self.string_offset()])

    def tag_length(self):
        return self._tag_length

    def length(self):
        return self.size()

    def verify(self):
        return self.flags() & 0x0b == 0 and \
            self.opcode() & 0x0F == 0x01
    
class CloseStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x02.

    This is the "close start element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("CloseStartElementNode at %s." % (hex(offset)))
        super(CloseStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseStartElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "CloseStartElementNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        return ">"

    def tag_length(self):
        return 1

    def length(self):
        return 1
    
    def children(self):
        return []

    def verify(self):
        return self.flags() & 0x0F == 0 and \
            self.opcode() & 0x0F == 0x02


class Node0x03(BXmlNode):
    """
    The binary XML node for the system token 0x03.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x03 at %s." % (hex(offset)))
        super(Node0x03, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x03(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x03(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x03")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x03")


class CloseElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x04.

    This is the "close element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("CloseElementNode at %s." % (hex(offset)))
        super(CloseElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "CloseElementNode(offset=%s)" % (hex(self._offset))

    def __xml__(self):
        return ""

    def tag_length(self):
        return 1

    def length(self):
        return 1
    
    def children(self):
        return []

    def verify(self):
        return self.flags() & 0x0F == 0 and \
            self.opcode() & 0x0F == 0x04


class ValueNode(BXmlNode):
    """
    The binary XML node for the system token 0x05.

    This is the "value" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("ValueNode at %s." % (hex(offset)))
        super(ValueNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "type")
        
        self._types = [
            NullTypeNode,
            WstringTypeNode,
            ]

    def __repr__(self):
        return "ValueNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "ValueNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        return "<<value %s>>" % (xml(self.children()[0]))

    def value(self):
        raise NotImplementedError("value not implemented for ValueNode")
    
    def tag_length(self):
        return 2

    def children(self):
        try:
            TypeClass = self._types[self.type()]
        except IndexError:
            raise NotImplementedError("Type %s not implemented" % \
                                          (self.type()))
        child = TypeClass(self._buf, self._offset + self.tag_length(),
                          self._chunk, self)
        return [child]

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.token() & 0x0F == 0x05


class AttributeNode(BXmlNode):
    """
    The binary XML node for the system token 0x06.

    This is the "attribute" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("AttributeNode at %s." % (hex(offset)))
        super(AttributeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")

        global indent
        
        self._data_length = 0
        if self.string_offset() > self._offset - self._chunk._offset:
            print indent, "%r" % (self), "need new string", self.string_offset()
            string_node = NameStringNode(self._buf, 
                                         self._chunk._offset + self.string_offset(),
                                         self._chunk,
                                         self._chunk)
            self._chunk.add_string(self.string_offset(), string_node)
            self._data_length += string_node.tag_length()

        print indent, "Attribute %s" % (self.attribute_name())

    def __repr__(self):
        return "AttributeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "AttributeNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        return " %s" % (self.attribute_name())

    def attribute_name(self):
        return xml(self._chunk.strings()[self.string_offset()])        
    
    def data_length(self):
        return self._data_length

    def tag_length(self):
        return 5

    def length(self):
        return self.tag_length() + self.data_length()

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.opcode() & 0x0F == 0x06


class Node0x07(BXmlNode):
    """
    The binary XML node for the system token 0x07.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x07 at %s." % (hex(offset)))
        super(Node0x07, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x07(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x07(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x07")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x07")


class Node0x08(BXmlNode):
    """
    The binary XML node for the system token 0x08.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x08 at %s." % (hex(offset)))
        super(Node0x08, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x08(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x08(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x08")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x08")

    def length(self):
        raise NotImplementedError("length not implemented for %r") % \
            (self)


class Node0x09(BXmlNode):
    """
    The binary XML node for the system token 0x09.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x09 at %s." % (hex(offset)))
        super(Node0x09, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x09(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x09(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x09")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x09")


class Node0x0A(BXmlNode):
    """
    The binary XML node for the system token 0x0A.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x0A at %s." % (hex(offset)))
        super(Node0x0A, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x0A(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x0A(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x0A")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x0A")


class Node0x0B(BXmlNode):
    """
    The binary XML node for the system token 0x0B.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x0B at %s." % (hex(offset)))
        super(Node0x0B, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x0B(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x0B(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x0B")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x0B")


class Node0x0C(BXmlNode):
    """
    The binary XML node for the system token 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x0C at %s." % (hex(offset)))
        super(Node0x0C, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x0C(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x0C(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x0C")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x0C")


class NormalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0D.

    This is a "normal substitution" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("NormalSubstitutionNode at %s." % (hex(offset)))
        super(NormalSubstitutionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

        global indent
        print indent, "Substitution", self


    def __repr__(self):
        return "NormalSubstitutionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "NormalSubstitutionNode(offset=%s, index=%d, type=%d)" % \
            (hex(self._offset), self.index(), self.type())
    
    def __xml__(self):
        return "<<Substitution index=%d type=%d>>" % \
            (self.index(), self.type())
    
    def tag_length(self):
        return 0x4

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0 and \
            self.token() & 0x0F == 0x0D

class Node0x0E(BXmlNode):
    """
    The binary XML node for the system token 0x0E.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x0E at %s." % (hex(offset)))
        super(Node0x0E, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x0E(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x0E(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x0E")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x0E")


class StreamStartNode(BXmlNode):
    """
    The binary XML node for the system token 0x0F.

    This is the "start of stream" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("StreamStartNode at %s." % (hex(offset)))
        super(StreamStartNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("word", "unknown1")

    def __repr__(self):
        return "StreamStartNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "StreamStartNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        # TODO(wb): implement this really
        return "<<StartOfStream>>"
    
    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == 0x0F and \
            self.unknown0() == 0x1 and \
            self.unknown1() == 0x1

    def tag_length(self):
        return 4

    def length(self):
        return self.tag_length() + 0

    def children(self):
        return []


class VariantTypeNode(BXmlNode):
    """

    """
    def __init__(self, buf, offset, chunk, parent):
        debug("VariantTypeNode at %s." % (hex(offset)))
        super(VariantTypeNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "VariantTypeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "VariantTypeNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for %r" % \
                                      (self))

    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for %r" % \
                                      (self))

    def length(self):
        return self.tag_length()
    
    def children(self):
        return []


class NullTypeNode(VariantTypeNode):
    def __init__(self, buf, offset, chunk, parent):
        debug("NullTypeNode at %s." % (hex(offset)))
        super(NullTypeNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "NullTypeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "NullTypeNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        return ""

    def tag_length(self):
        return 0


class WstringTypeNode(VariantTypeNode):
    """

    """
    def __init__(self, buf, offset, chunk, parent):
        debug("WstringTypeNode at %s." % (hex(offset)))
        super(WstringTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("word",    "size", 0x0)
        self.declare_field("wstring", "string", length=(self.size() / 2))

    def __repr__(self):
        return "WstringTypeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "WstringTypeNode(offset=%s, string=%s)" % \
            (hex(self._offset), self.string())
    
    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 2 + self.size()


import itertools

from BinaryParser import *



def xml(item):
    return item.__xml__()


indent = ""

class SYSTEM_TOKENS:
    EndOfStreamToken = 0x00
    OpenStartElementToken = 0x01
    CloseStartElementToken = 0x02
    CloseEmptyElementToken = 0x03
    CloseElementToken = 0x04
    ValueToken = 0x05
    AttributeToken = 0x06
    CDataSectionToken = 0x07
    EntityReferenceToken = 0x08
    ProcessingInstructionTargetToken = 0x0A
    ProcessingInstructionDataToken = 0x0B
    TemplateInstanceToken = 0x0C
    NormalSubstitutionToken = 0x0D
    ConditionalSubstitutionToken = 0x0E
    StartOfStreamToken = 0x0F


class BXmlNode(Block):
    def __init__(self, buf, offset, chunk, parent):
        debug("BXmlNode at %s." % (hex(offset)))
        super(BXmlNode, self).__init__(buf, offset)
        self._chunk = chunk
        self._parent = parent
        self._dispatch_table = [
            EndOfStreamNode,
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
            ConditionalSubstitutionNode,
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
            "Normal Substitution",
            "Conditional Substitution",
            "Start of Stream",            
            ]


    def __repr__(self):
        return "BXmlNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "BXmlNode(offset=%s)" % (hex(self._offset))

    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for %r") % (self)

    def dump(self):
        return hex_dump(self._buf[self._offset:self._offset + self.length()],
                        start_addr=self._offset)

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

    def _children(self, max_children=None, 
                  end_tokens=[SYSTEM_TOKENS.EndOfStreamToken]):
        """
        @return A list containing all of the children BXmlNodes.
        """
        ret = []
        ofs = self.tag_length()

        global indent
        print ".,", indent, self.__class__.__name__, "children"

        indent += "\t"

        if max_children:
            gen = xrange(max_children)
        else:
            gen = itertools.count()

        for _ in gen:
            # we lose error checking by masking off the higher nibble,
            #   but, some tokens like 0x01, make use of the flags nibble.
            token = self.unpack_byte(ofs) & 0x0F
            print ".,", indent, "token", hex(token), \
                "(%s)" % self._readable_tokens[token], \
                "@", hex(self._offset + ofs)
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
            if token in end_tokens:
                break
        indent = indent[:-2]

        return ret

    #@memoize
    def children(self):
        return self._children()

    #@memoize
    def length(self):
        """
        @return An integer specifying the length of this tag and all
          its children.
        """
        ret = self.tag_length()
        for child in self.children():
            ret += child.length()
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
        return "NameStringNode(offset=%s, length=%s)" % (hex(self._offset), hex(self.length()))
    
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
        return "TemplateNode(offset=%s, guid=%s, length=%s)" % \
            (hex(self._offset), self.guid(), hex(self.length()))
    
    def __xml__(self):
        # TODO(wb): this.
        cxml = "".join(xml(c) for c in self.children())
        return "<<template %s>>%s<</template %s>>" % (self.guid(), 
                                                        cxml,
                                                        self.guid())
        return self.guid()
    
    def tag_length(self):
        return 0x18

    def length(self):
        return self.tag_length() + self.data_length()

class EndOfStreamNode(BXmlNode):
    """
    The binary XML node for the system token 0x00.

    This is the "end of stream" token. It may never actually
      be instantiated here.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("EndOfStreamNode at %s." % (hex(offset)))
        super(EndOfStreamNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "EndOfStreamNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "EndOfStreamNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), 0x00)
    
    def __xml__(self):
        return ""
    
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
            print ".,", indent, "%r" % (self), "need new string", self.string_offset()
            string_node = NameStringNode(self._buf, 
                                         self._chunk._offset + self.string_offset(),
                                         self._chunk,
                                         self._chunk)
            self._chunk.add_string(self.string_offset(), string_node)
            self._tag_length += string_node.tag_length()

        #print ".,", indent, "Start Element", self, "tag length", self.tag_length()

    def __repr__(self):
        return "OpenStartElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "OpenStartElementNode(offset=%s, name=%s, length=%s, token=%s)" % \
            (hex(self._offset), self.tag_name(), 
             hex(self.length()), hex(self.token()))
    
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

    def verify(self):
        return self.flags() & 0x0b == 0 and \
            self.opcode() & 0x0F == 0x01

    def children(self):
        return self._children(end_tokens=[SYSTEM_TOKENS.CloseElementToken])
    

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
        return "CloseStartElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(self.token()))
    
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
        return "Node0x03(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x03))
    
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
        return "CloseElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(self.token()))

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
        return "ValueNode(offset=%s, length=%s, token=%s, value=%s)" % \
            (hex(self._offset), hex(self.length()), 
             hex(self.token()), xml(self))
    
    def __xml__(self):
        return xml(self.children()[0])

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
            self.token() & 0x0F == SYSTEM_TOKENS.ValueToken


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
            print ".,", indent, "%r" % (self), "need new string", self.string_offset()
            string_node = NameStringNode(self._buf, 
                                         self._chunk._offset + self.string_offset(),
                                         self._chunk,
                                         self._chunk)
            self._chunk.add_string(self.string_offset(), string_node)
            self._data_length += string_node.tag_length()

        print ".,", indent, "Attribute %s" % (self.attribute_name())

    def __repr__(self):
        return "AttributeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "AttributeNode(offset=%s, length=%s, token=%s, name=%s, value=%s)" % \
            (hex(self._offset), hex(self.length()), hex(self.token()), 
             self.attribute_name(), self.attribute_value())
    
    def __xml__(self):
        return " %s=\"%s\"" % (self.attribute_name(), self.attribute_value())

    def attribute_name(self):
        return xml(self._chunk.strings()[self.string_offset()])        
    
    def attribute_value(self):
        return xml(self.children()[0])

    def data_length(self):
        return self._data_length

    def tag_length(self):
        return 5

    def length(self):
        clength = 0
        for c in self.children():
            clength += c.length()
        return self.tag_length() + self.data_length() + clength

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.opcode() & 0x0F == 0x06

    def children(self):
        ofs = self.tag_length()
        token = self.unpack_byte(ofs) & 0x0F
        print ".,", indent, "token", hex(token), \
            "(%s)" % self._readable_tokens[token], \
            "@", hex(self._offset + ofs)
        try:
            HandlerNodeClass = self._dispatch_table[token]
            child = HandlerNodeClass(self._buf, self._offset + ofs, 
                                     self._chunk, self)
            return [child]
        except IndexError:
            raise ParseException("Unexpected token %02X at %s" % \
                                     (token, 
                                      self.absolute_offset(0x0) + ofs))


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
        return "Node0x07(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), 0x07)
    
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
        return "Node0x08(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x08))
    
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
        return "Node0x09(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x09))
    
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
        return "Node0x0A(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x0A))
    
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
        return "Node0x0B(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x0B))
    
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
        return "Node0x0C(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x0C))
    
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
        print ".,", indent, "Normal Substitution", self


    def __repr__(self):
        return "NormalSubstitutionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "NormalSubstitutionNode(offset=%s, length=%s, token=%s, index=%d, type=%d)" % \
            (hex(self._offset), hex(self.length()), hex(self.token()), 
             self.index(), self.type())
    
    def __xml__(self):
        return "[[Normal Substitution index=%d type=0x%02X]]" % \
            (self.index(), self.type())
    
    def tag_length(self):
        return 0x4

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.NormalSubstitutionToken

class ConditionalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0E.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("ConditionalSubstitutionNode at %s." % (hex(offset)))
        super(ConditionalSubstitutionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

        global indent
        print ".,", indent, "Conditional Substitution", self


    def __repr__(self):
        return "ConditionalSubstitutionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "ConditionalSubstitutionNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x0E))
    
    def __xml__(self):
        return "[[Conditional Substitution index=%d type=0x%02X]]" % \
            (self.index(), self.type())
    
    def tag_length(self):
        return 0x4

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.ConditionalSubstitutionToken



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
        return "StreamStartNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(self.token()))
    
    def __xml__(self):
        return ""
    
    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.StartOfStreamToken and \
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
        return "VariantTypeNode(offset=%s, length=%s)" % (hex(self._offset), hex(self.length()))
    
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
        return "NullTypeNode(offset=%s, length=%s)" % (hex(self._offset), hex(self.length()))
    
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
        self.declare_field("word",    "string_length", 0x0)
        self.declare_field("wstring", "string", length=(self.string_length()))

    def __repr__(self):
        return "WstringTypeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "WstringTypeNode(offset=%s, length=%s, string=%s)" % \
            (hex(self._offset), hex(self.length()), self.string())
    
    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 2 + (self.string_length() * 2)


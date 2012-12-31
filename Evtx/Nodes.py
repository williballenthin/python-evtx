import itertools
import base64

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
            CloseEmptyElementNode,
            CloseElementNode,
            ValueNode,
            AttributeNode,
            CDataSectionNode,
            None,
            Node0x09,
            Node0x0A,
            Node0x0B,
            TemplateInstanceNode,
            NormalSubstitutionNode,
            ConditionalSubstitutionNode,
            StreamStartNode,
            ]
        self._readable_tokens = [
            "End of Stream",
            "Open Start Element",
            "Close Start Element",
            "Close Empty Element",
            "Close Element",
            "Value",
            "Attribute",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "TemplateInstanceNode",
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

    @memoize
    def length(self):
        """
        @return An integer specifying the length of this tag and all
          its children.
        """
        ret = self.tag_length()
        for child in self.children():
            ret += child.length()
        return ret

    def find_end_of_stream(self):
        for child in self.children():
            if type(child) == EndOfStreamNode:
                return child
            ret = child.find_end_of_stream()
            if ret:
                return ret
        return None


class NameStringNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        debug("NameStringNode at %s." % (hex(offset)))
        super(NameStringNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("word", "hash")
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "string", length=self.string_length())

        debug("Same %s" % (self))

    def __repr__(self):
        return "NameStringNode(buf=%r, offset=%r, chunk=%r)" % \
            (self._buf, self._offset, self._chunk)

    def __str__(self):
        return "NameStringNode(offset=%s, length=%s, end=%s)" % \
            (hex(self._offset), hex(self.length()), 
             hex(self._offset + self.length()))
    
    def __xml__(self):
        return str(self.string())
    
    def tag_length(self):
        return (self.string_length() * 2) + 8

    def length(self):
        # two bytes unaccounted for...
        return self.tag_length() + 2


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
        # TODO(wb): use this size() field.
        self.declare_field("dword", "size")
        self.declare_field("dword", "string_offset")
        self._tag_length = 11
        self._element_type = 0

        if self.flags() & 0x04:
            self._tag_length += 4
            debug("Has extra four, total length %s" % (self._tag_length))

        global indent
        if self.string_offset() > self._offset - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(), 
                                                parent=self)
            self._tag_length += new_string.length()
            debug("Has embedded string, total length %s" % (hex(self._tag_length)))

        debug("Same %s" % (self))

    def __repr__(self):
        return "OpenStartElementNode(buf=%r, offset=%r, chunk=%r)" % \
            (self._buf, self._offset, self._chunk)

    def __str__(self):
        return "OpenStartElementNode(offset=%s, name=%s, length=%s, token=%s, end=%s, taglength=%s, endtag=%s)" % \
            (hex(self._offset), self.tag_name(), 
             hex(self.length()), hex(self.token()), 
             hex(self._offset + self.length()), 
             hex(self.tag_length()),
             hex(self._offset + self.tag_length()))
    
    def __xml__(self):
        cxml = "".join(xml(c) for c in self.children())
        ret = "\n<%s%s" % (self.tag_name(), cxml)
        if not self.is_empty_node():
            ret += "</%s>" % (self.tag_name())
        return ret

    def is_empty_node(self):
        for child in self.children():
            if type(child) is CloseEmptyElementNode:
                return True
        return False

    def tag_name(self):
        return xml(self._chunk.strings()[self.string_offset()])

    def tag_length(self):
        return self._tag_length

#    def length(self):
#        return self.size() + 0x6

    def verify(self):
        return self.flags() & 0x0b == 0 and \
            self.opcode() & 0x0F == 0x01

    def children(self):
        return self._children(end_tokens=[SYSTEM_TOKENS.CloseElementToken,
                                          SYSTEM_TOKENS.CloseEmptyElementToken])
    

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


class CloseEmptyElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x03.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("CloseEmptyElementNode at %s." % (hex(offset)))
        super(CloseEmptyElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseEmptyElementNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "CloseEmptyElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x03))
    
    def __xml__(self):
        return " />"
    
    def tag_length(self):
        return 1
    
    def length(self):
        return 1

    def children(self):
        return []

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


def get_variant_value(buf, offset, chunk, parent, type_):
    """
    @return A VariantType subclass instance found in the given 
      buffer and offset.
    """
    types = [
        NullTypeNode,          # 0x00
        WstringTypeNode,       # 0x01
        StringTypeNode,        # 0x02
        SignedByteTypeNode,    # 0x03
        UnsignedByteTypeNode,  # 0x04
        SignedWordTypeNode,    # 0x05
        UnsignedWordTypeNode,  # 0x06
        SignedDwordTypeNode,   # 0x07
        UnsignedDwordTypeNode, # 0x08
        SignedQwordTypeNode,   # 0x09
        UnsignedQwordTypeNode, # 0x0A
        FloatTypeNode,         # 0x0B
        DoubleTypeNode,        # 0x0C
        ]
    try:
        TypeClass = types[type_]
    except IndexError:
        raise NotImplementedError("Type %s not implemented" % (type_))
    return TypeClass(buf, offset, chunk, parent)


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
        return self.children()[0]
    
    def tag_length(self):
        return 2

    def children(self):
        child = get_variant_value(self._buf, 
                                  self._offset + self.tag_length(),
                                  self._chunk, self, self.type())
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
        
        self._name_string_length = 0
        if self.string_offset() > self._offset - self._chunk._offset:
            print ".,", indent, "%r" % (self), "need new string", self.string_offset()
            new_string = self._chunk.add_string(self.string_offset(), 
                                                parent=self)
            self._name_string_length += new_string.length()

        print ".,", indent, "Attribute name %s" % (xml(self.attribute_name()))
        print hex(self._offset), hex(self.tag_length()), hex(self._offset + self.tag_length()), hex(self.length()), hex(self._offset + self.length())
        print ".;", indent, "Attribute value %s" % (self.children())

        debug("Again %s" % (self))

    def __repr__(self):
        return "AttributeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "AttributeNode(offset=%s, length=%s, token=%s, name=%s, value=%s)" % \
            (hex(self._offset), hex(self.length()), hex(self.token()), 
             self.attribute_name(), self.attribute_value())
    
    def __xml__(self):
        return " %s=\"%s\"" % (xml(self.attribute_name()), 
                               xml(self.attribute_value()))

    def attribute_name(self):
        """
        @return A NameNode instance that contains the attribute name.
        """
        return self._chunk.strings()[self.string_offset()]
    
    def attribute_value(self):
        """
        @return A BXmlNode instance that is one of (ValueNode,
          ConditionalSubstitutionNode, NormalSubstitutionNode).
        """
        return self.children()[0]

    def tag_length(self):
        return 5 + self._name_string_length

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.opcode() & 0x0F == 0x06

    def children(self):
        return self._children(max_children=1)


class CDataSectionNode(BXmlNode):
    """
    The binary XML node for the system token 0x07.

    This is the "CDATA section" system token.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("CDataSectionNode at %s." % (hex(offset)))
        super(CDataSectionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "cdata", length=self.string_length() - 2)

    def __repr__(self):
        return "CDataSectionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "CDataSectionNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), 0x07)
    
    def __xml__(self):
        return "<![CDATA[%s]]>" % (self.cdata())
    
    def tag_length(self):
        return 0x3 + self.string_length()

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.CDataSectionToken


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


class TemplateInstanceNode(BXmlNode):
    """
    The binary XML node for the system token 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("TemplateInstanceNode at %s." % (hex(offset)))
        super(TemplateInstanceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("dword", "template_id")
        self.declare_field("dword", "template_offset")

        self._data_length = 0

        if self.is_resident_template():
            print ".,", indent, "%r" % (self), "need new template", self.template_offset()
            new_template = self._chunk.add_template(self.template_offset(), 
                                                    parent=self)
            self._data_length += new_template.length()

    def __repr__(self):
        return "TemplateInstanceNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "TemplateInstanceNode(offset=%s, length=%s, token=%s)" % \
            (hex(self._offset), hex(self.length()), hex(0x0C))
    
    def __xml__(self):
        return xml(self._chunk.templates()[self.template_offset()])

    def is_resident_template(self):
        return self.template_offset() > self._offset - self._chunk._offset

    def tag_length(self):
        return 10

    def length(self):
        return self.tag_length() + self._data_length

    def template(self):
        return self._chunk.templates()[self.template_offset()]

    def children(self):
        return []

    def find_end_of_stream(self):
        if self.is_resident_template():
            return self.template().find_end_of_stream()
        return None


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


class RootNode(BXmlNode):
    """
    The binary XML node for the Root node.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("RootNode at %s." % (hex(offset)))
        super(RootNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "RootNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "RootNode(offset=%s, length=%s)" % \
            (hex(self._offset), hex(self.length()))
    
    def __xml__(self):
        return "RootNode"

    def tag_length(self):
        return 0

    def children(self):
        """
        @return The template instances which make up this node.
        """
        # TODO(wb): I really don't know if this is correct.
        # TODO(wb): Can we have more than one TemplateInstance here?
        return self._children(end_tokens=[SYSTEM_TOKENS.EndOfStreamToken])

    def substitutions(self):
        """
        @return A list of VariantTypeNode subclass instances that contain the 
          substitions for this root node.
        """
        sub_decl = []
        sub_def = []
        ofs = self.find_end_of_stream()._offset - self._offset + 1
        sub_count = self.unpack_dword(ofs)
        debug("count: %s" % (sub_count))
        ofs += 4
        for _ in xrange(sub_count):
            size = self.unpack_word(ofs)
            type_ = self.unpack_byte(ofs + 0x2)
            sub_decl.append((size, type_))
            ofs += 4
        debug(sub_decl)
        for (size, type_) in sub_decl:
            val = get_variant_value(self._buf, self._offset + ofs, 
                                  self._chunk, self, type_)
            if size != val.length():
                raise ParseException("Invalid substitution value size")
            sub_def.append(val)
            ofs += size
        return sub_def


class VariantTypeNode(BXmlNode):
    """

    """
    def __init__(self, buf, offset, chunk, parent):
        debug("VariantTypeNode at %s." % (hex(offset)))
        super(VariantTypeNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "%s(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self.__class__.__name___, self._buf, self._offset, 
             self._chunk, self._parent)

    def __str__(self):
        return "%s(offset=%s, length=%s, string=%s)" % \
            (self.__class__.__name___, hex(self._offset), 
             hex(self.length()), self.string())
    
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
    
    def string(self):
        raise NotImplementedError("string not implemented for %r" % \
                                      (self))


class NullTypeNode(VariantTypeNode):
    """
    Variant type 0x00.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(NullTypeNode, self).__init__(buf, offset, chunk, parent)

    def __xml__(self):
        return ""

    def string(self):
        return "NULL"

    def tag_length(self):
        return 0


class WstringTypeNode(VariantTypeNode):
    """
    Variant ttype 0x01.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(WstringTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("word",    "string_length", 0x0)
        self.declare_field("wstring", "string", length=(self.string_length()))

    def __xml__(self):
        # ensure this is a str, not unicode
        return str(self.string())

    def tag_length(self):
        return 2 + (self.string_length() * 2)


class StringTypeNode(VariantTypeNode):
    """
    Variant ttype 0x02.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(StringTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("word",   "string_length", 0x0)
        self.declare_field("string", "string", length=(self.string_length()))

    def __xml__(self):
        return str(self.string())

    def tag_length(self):
        return 2 + (self.string_length())


class SignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x03.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedByteTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("int8", "byte", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class UnsignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x04.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedByteTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("byte", "byte", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class SignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x05.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedWordTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("int16", "word", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class UnsignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x06.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedWordTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("word", "word", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class SignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x07.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedDwordTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("int32", "dword", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class UnsignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x08.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedDwordTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("dword", "dword", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class SignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x09.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedQwordTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("int64", "qword", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class UnsignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x0A.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedQwordTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("qword", "qword", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class FloatTypeNode(VariantTypeNode):
    """
    Variant type 0x0B.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(FloatTypeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("float", "float", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 4

    def string(self):
        return str(self.float())


class DoubleTypeNode(VariantTypeNode):
    """
    Variant type 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(DoubleTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("double", "double", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 8

    def string(self):
        return str(self.double())


class BooleanTypeNode(VariantTypeNode):
    """
    Variant type 0x0D.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(BooleanTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("int32", "int32", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 4

    def string(self):
        if self.int32 > 0:
            return "True"
        return "False"


class BinaryTypeNode(VariantTypeNode):
    """
    Variant type 0x0E.

    String/XML representation is Base64 encoded.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(BinaryTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("dword", "size", 0x0)
        self.declare_field("binary", "binary", length=self.size())

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 4 + self.size()

    def string(self):
        return base64.b64encode(self.binary())


class GuidTypeNode(VariantTypeNode):
    """
    Variant type 0x0F.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(GuidTypeNode, self).__init__(buf, offset, 
                                                   chunk, parent)
        self.declare_field("guid", "guid", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 16

    def string(self):
        return self.guid()


class SizeTypeNode(VariantTypeNode):
    """
    Variant type 0x10.

    Note: Assuming sizeof(size_t) == 0x8.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SizeTypeNode, self).__init__(buf, offset, 
                                           chunk, parent)
        self.declare_field("qword", "qword", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class FiletimeTypeNode(VariantTypeNode):
    """
    Variant type 0x11.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(FiletimeTypeNode, self).__init__(buf, offset, 
                                           chunk, parent)
        self.declare_field("filetime", "filetime", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 8

    def string(self):
        return self.filetime().isoformat("T") + "Z"


class SystemtimeTypeNode(VariantTypeNode):
    """
    Variant type 0x12.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SystemtimeTypeNode, self).__init__(buf, offset, 
                                           chunk, parent)
        self.declare_field("systemtime", "systemtime", 0x0)

    def __xml__(self):
        return self.string()

    def tag_length(self):
        return 16

    def string(self):
        return self.systemtime().isoformat("T") + "Z"


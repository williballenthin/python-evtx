#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.0.1

import itertools
import base64

from BinaryParser import *


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


class SuppressConditionalSubstitution(Exception):
    """
    This exception is to be thrown to indicate that a conditional
      substitution evaluated to NULL, and the parent element should
      be suppressed. This exception should be caught at the first
      opportunity, and must not propagate far up the call chain.

    Strategy:
      AttributeNode catches this, .xml() --> ""
      StartOpenElementNode catches this for each child, ensures
        there's at least one useful value.  Or, .xml() --> ""
    """
    def __init__(self, msg):
        super(SuppressConditionalSubstitution, self).__init__(msg)


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
            EntityReferenceNode,
            ProcessingInstructionTargetNode,
            ProcessingInstructionDataNode,
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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "BXmlNode(offset=%s)" % (hex(self.offset()))

    def xml(self, substitutions):
        raise NotImplementedError("xml() not implemented for %r") % (self)

    def template_format(self):
        raise NotImplementedError("template_format() not implemented for %r") % (self)

    def dump(self):
        return hex_dump(self._buf[self.offset():self.offset() + self.length()],
                        start_addr=self.offset())

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
        debug(".,", indent, self.__class__.__name__, "children")

        indent += "\t"

        if max_children:
            gen = xrange(max_children)
        else:
            gen = itertools.count()

        for _ in gen:
            # we lose error checking by masking off the higher nibble,
            #   but, some tokens like 0x01, make use of the flags nibble.
            token = self.unpack_byte(ofs) & 0x0F
            debug(".,", indent, "token", hex(token), \
                "(%s)" % self._readable_tokens[token], \
                "@", hex(self.offset() + ofs))
            try:
                HandlerNodeClass = self._dispatch_table[token]
                child = HandlerNodeClass(self._buf, self.offset() + ofs,
                                         self._chunk, self)
            except IndexError:
                raise ParseException("Unexpected token %02X at %s" % \
                                         (token,
                                          self.absolute_offset(0x0) + ofs))
            ret.append(child)
            ofs += child.length()
            if token in end_tokens:
                break
            if child.find_end_of_stream():
                break
        indent = indent[:-2]

        return ret

    @memoize
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

    @memoize
    def find_end_of_stream(self):
        for child in self.children():
            if isinstance(child, EndOfStreamNode):
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
            (self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "NameStringNode(offset=%s, length=%s, end=%s)" % \
            (hex(self.offset()), hex(self.length()),
             hex(self.offset() + self.length()))

    def string(self):
        return str(self._string())

    def xml(self, substitutions):
        return self.string()

    def template_format(self):
        return self.xml([])

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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "TemplateNode(offset=%s, guid=%s, length=%s)" % \
            (hex(self.offset()), self.guid(), hex(self.length()))

    def xml(self, substitutions):
        ret = ""
        for child in self.children():
            ret += child.xml(substitutions)
        return ret

    def template_format(self):
        ret = ""
        for child in self.children():
            ret += child.template_format()
        return ret

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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "EndOfStreamNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), 0x00)

    def xml(self, substitutions):
        return ""

    def template_format(self):
        return self.xml([])

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
        if self.string_offset() > self.offset() - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()
            debug("Has embedded string, total length %s" % (hex(self._tag_length)))

        debug("Same %s" % (self))

    def __repr__(self):
        return "OpenStartElementNode(buf=%r, offset=%r, chunk=%r)" % \
            (self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "OpenStartElementNode(offset=%s, name=%s, length=%s, token=%s, end=%s, taglength=%s, endtag=%s)" % \
            (hex(self.offset()), self.tag_name(),
             hex(self.length()), hex(self.token()),
             hex(self.offset() + self.length()),
             hex(self.tag_length()),
             hex(self.offset() + self.tag_length()))

    def xml(self, substitutions):
        """
        @return A string containing an XML fragment representation of
          this element and its descendants.  The return value may be the
          empty string if all values were conditionally suppressed. If only
          some values are conditionally suppressed, let's use this strategy:

          Some active attributes, some active children:
            <tag attr=".."> children </tag>
          No active attributes, some active children:
            <tag> children </tag>
          Some active attributes, no active children:
            <tag attr=".." />
          No active attributes, no active children:
            (empty string)
        """
        attr_xml = ""
        for child in self.children():
            if isinstance(child, AttributeNode):
                attr_xml += child.xml(substitutions)
        # this is a hack using the length of the XML :-(
        has_attr_xml = len(attr_xml) != 0

        num_active_children = 0
        for child in self.children():
            if isinstance(child, (ValueNode, CDataSectionNode,
                                  EntityReferenceNode, ProcessingInstructionTargetNode, ProcessingInstructionDataNode,
                                  TemplateInstanceNode,
                                  NormalSubstitutionNode,
                                  OpenStartElementNode)):
                num_active_children += 1
            elif isinstance(child, ConditionalSubstitutionNode) and \
                    not child.should_suppress(substitutions):
                num_active_children += 1

        if (self.is_empty_node() or num_active_children == 0) \
                and not has_attr_xml:
            return ""
        if (self.is_empty_node() or num_active_children == 0) \
                and has_attr_xml:
            return "\n<%s%s />" % (self.tag_name(), attr_xml)
        else: # num_active_children != 0 and has_attr_xml
            cxml = "".join(c.xml(substitutions) for c in self.children())
            return "\n<%s%s</%s>" % (self.tag_name(), cxml, self.tag_name())

    def template_format(self):
        children_string = ""
        for child in self.children():
            children_string += child.template_format()
        if self.is_empty_node():
            return "\n<%s%s />" % (self.tag_name(), children_string)
        else:
            return "\n<%s%s</%s>" % (self.tag_name(), children_string, 
                                     self.tag_name())

    @memoize
    def is_empty_node(self):
        for child in self.children():
            if type(child) is CloseEmptyElementNode:
                return True
        return False

    @memoize
    def tag_name(self):
        return self._chunk.strings()[self.string_offset()].string()

    def tag_length(self):
        return self._tag_length

    def verify(self):
        return self.flags() & 0x0b == 0 and \
            self.opcode() & 0x0F == 0x01

    @memoize
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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseStartElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()))

    def xml(self, substitutions):
        return ">"

    def template_format(self):
        return self.xml([])

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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseEmptyElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x03))

    def xml(self, substitutions):
        return ""

    def template_format(self):
        return self.xml([])

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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseElementNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()))

    def xml(self, substitutions):
        return ""

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []

    def verify(self):
        return self.flags() & 0x0F == 0 and \
            self.opcode() & 0x0F == 0x04


def get_variant_value(buf, offset, chunk, parent, type_, length=None):
    """
    @return A VariantType subclass instance found in the given
      buffer and offset.
    """
    types = {
        0x00: NullTypeNode,
        0x01: WstringTypeNode,
        0x02: StringTypeNode,
        0x03: SignedByteTypeNode,
        0x04: UnsignedByteTypeNode,
        0x05: SignedWordTypeNode,
        0x06: UnsignedWordTypeNode,
        0x07: SignedDwordTypeNode,
        0x08: UnsignedDwordTypeNode,
        0x09: SignedQwordTypeNode,
        0x0A: UnsignedQwordTypeNode,
        0x0B: FloatTypeNode,
        0x0C: DoubleTypeNode,
        0x0D: BooleanTypeNode,
        0x0E: BinaryTypeNode,
        0x0F: GuidTypeNode,
        0x10: SizeTypeNode,
        0x11: FiletimeTypeNode,
        0x12: SystemtimeTypeNode,
        0x13: SIDTypeNode,
        0x14: Hex32TypeNode,
        0x15: Hex64TypeNode,
        0x21: BXmlTypeNode,
        0x81: WstringArrayTypeNode
    }
    try:
        TypeClass = types[type_]
    except IndexError:
        raise NotImplementedError("Type %s not implemented" % (type_))
    return TypeClass(buf, offset, chunk, parent, length=length)


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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ValueNode(offset=%s, length=%s, token=%s, value=%s)" % \
            (hex(self.offset()), hex(self.length()),
             hex(self.token()), self.xml([]))

    def xml(self, substitutions):
        return self.children()[0].xml()

    def template_format(self):
        return self.xml([])

    def value(self):
        return self.children()[0]

    def tag_length(self):
        return 2

    def children(self):
        child = get_variant_value(self._buf,
                                  self.offset() + self.tag_length(),
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
        if self.string_offset() > self.offset() - self._chunk._offset:
            debug(".,", indent, "%r" % (self), "need new string", self.string_offset())
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._name_string_length += new_string.length()

        debug(".,", indent, "Attribute name %s" % (self.attribute_name().xml([])))
        debug(hex(self.offset()), hex(self.tag_length()), hex(self.offset() + self.tag_length()), hex(self.length()), hex(self.offset() + self.length()))
        debug(".;", indent, "Attribute value %s" % (self.children()))

        debug("Again %s" % (self))

    def __repr__(self):
        return "AttributeNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "AttributeNode(offset=%s, length=%s, token=%s, name=%s, value=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()),
             self.attribute_name(), self.attribute_value())

    def xml(self, substitutions):
        """
        @return A string containing an XML fragment representation of this
          attribute.  This string may be empty if the value of the
          attribute was conditionally suppressed.
        """
        name = self.attribute_name().xml(substitutions)
        val = self.attribute_value()
        debug("C", val, type(val), isinstance(val, ConditionalSubstitutionNode))
        if isinstance(val, ConditionalSubstitutionNode) and \
                val.should_suppress(substitutions):
            debug("SUPRESSING", name, val)
            return ""
        return " %s=\"%s\"" % (name, val.xml(substitutions))

    def template_format(self):
        name = self.attribute_name().template_format()
        val = self.attribute_value().template_format()
        return " %s=\"%s\"" % (name, val)

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

    @memoize
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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CDataSectionNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), 0x07)

    def xml(self, substitutions):
        return "<![CDATA[%s]]>" % (self.cdata())

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 0x3 + self.string_length()

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.CDataSectionToken


class EntityReferenceNode(BXmlNode):
    """
    The binary XML node for the system token 0x09.
    
    This is an entity reference node.  That is, something that represents
      a non-XML character, eg. & --> &amp;.

    TODO(wb): this is untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("EntityReferenceNode at %s." % (hex(offset)))
        super(EntityReferenceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()


    def __repr__(self):
        return "EntityReferenceNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "EntityReferenceNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x09))

    def xml(self, substitutions):
        return "&%s;" % \
            (self._chunk.strings()[self.string_offset()].string())

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []

    def flags(self):
        return self.token() >> 4


class ProcessingInstructionTargetNode(BXmlNode):
    """
    The binary XML node for the system token 0x0A.

    TODO(wb): untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("ProcessingInstructionTargetNode at %s." % (hex(offset)))
        super(ProcessingInstructionTargetNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "ProcessingInstructionTargetNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ProcessingInstructionTargetNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0A))

    def xml(self, substitutions):
        return "<?%s" % \
            (self._chunk.strings()[self.string_offset()].string())

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []

    def flags(self):
        return self.token() >> 4


class ProcessingInstructionDataNode(BXmlNode):
    """
    The binary XML node for the system token 0x0B.

    TODO(wb): untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("ProcessingInstructionDataNode at %s." % (hex(offset)))
        super(ProcessingInstructionDataNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self._tag_length = 3 + (2 * self.string_length())

        if self.string_length() > 0:
            self._string = self.unpack_wstring(0x3, self.string_length())
        else:
            self._string = ""
        
    def __repr__(self):
        return "ProcessingInstructionDataNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ProcessingInstructionDataNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0B))

    def xml(self, substitutions):
        if self.string_length() > 0:
            return " %s?>" % (self._string)
        else:
            return "?>"

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []

    def flags(self):
        return self.token() >> 4


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
            debug(".,", indent, "%r" % (self), \
                      "need new template", self.template_offset())
            new_template = self._chunk.add_template(self.template_offset(),
                                                    parent=self)
            self._data_length += new_template.length()

    def __repr__(self):
        return "TemplateInstanceNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "TemplateInstanceNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0C))

    def xml(self, substitutions):
        template = self._chunk.templates()[self.template_offset()]
        return template.xml(substitutions)

    def is_resident_template(self):
        return self.template_offset() > self.offset() - self._chunk._offset

    def tag_length(self):
        return 10

    def length(self):
        return self.tag_length() + self._data_length

    def template(self):
        return self._chunk.templates()[self.template_offset()]

    def children(self):
        return []

    @memoize
    def find_end_of_stream(self):
        return self.template().find_end_of_stream()


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
        debug(".,", indent, "Normal Substitution", self)

    def __repr__(self):
        return "NormalSubstitutionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "NormalSubstitutionNode(offset=%s, length=%s, token=%s, index=%d, type=%d)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()),
             self.index(), self.type())

    def xml(self, substitutions):
        # TODO(wb): verify type
        return substitutions[self.index()].xml()

    def template_format(self):
        return "[Normal Substitution(index=%s, type=%s)]" % \
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
        debug(".,", indent, "Conditional Substitution", self)


    def __repr__(self):
        return "ConditionalSubstitutionNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ConditionalSubstitutionNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(0x0E))

    def should_suppress(self, substitutions):
        sub = substitutions[self.index()]
        debug("D", sub, type(sub) is NullTypeNode)
        return type(sub) is NullTypeNode

    def xml(self, substitutions):
        if self.should_suppress(substitutions):
            return "WARNING: THIS ELEMENT SHOULD BE SUPPRESSED"
        return substitutions[self.index()].xml()

    def template_format(self):
        return "[Conditional Substitution(index=%s, type=%s)]" % \
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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "StreamStartNode(offset=%s, length=%s, token=%s)" % \
            (hex(self.offset()), hex(self.length()), hex(self.token()))

    def xml(self, substitutions):
        return ""

    def template_format(self):
        return self.xml([])

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
            (self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "RootNode(offset=%s, length=%s)" % \
            (hex(self.offset()), hex(self.length()))

    def xml(self, substitutions):
        """
        @param substitutions A list of substitutions, which for this
          RootNode, will override the substitutions stored in this
          element.  Provide the empty list to use the substitutions
          stored in this element, as expected.
        @return A string containing an XML fragment representation
          off this element and its descendants.
        """
        cxml = ""
        for child in self.children():
            cxml += child.xml(substitutions or self.substitutions())
        return cxml

    def tag_length(self):
        return 0

    @memoize
    def children(self):
        """
        @return The template instances which make up this node.
        """
        # TODO(wb): I really don't know if this is correct.
        # TODO(wb): Can we have more than one TemplateInstance here?
        return self._children(end_tokens=[SYSTEM_TOKENS.EndOfStreamToken])

    def tag_and_children_length(self):
        """
        @return The length of the tag of this element, and the children.
          This does not take into account the substitutions that may be
          at the end of this element.
        """
        children_length = 0

        for child in self.children():
            children_length += child.length()

        return self.tag_length() + children_length

    @memoize
    def substitutions(self):
        """
        @return A list of VariantTypeNode subclass instances that
          contain the substitutions for this root node.
        """
        sub_decl = []
        sub_def = []
        ofs = self.tag_and_children_length()
        debug("subs begin at %s" % (hex(self.offset() + ofs)))
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
            val = get_variant_value(self._buf, self.offset() + ofs,
                                    self._chunk, self, type_, length=size)
            if abs(size - val.length()) > 4:
                # TODO(wb): This is a hack, so I'm sorry.
                #   But, we are not passing around a 'length' field,
                #   so we have to depend on the structure of each
                #   variant type.  It seems some BXmlTypeNode sizes
                #   are not exact.  Hopefully, this is just alignment.
                #   So, that's what we compensate for here.
                debug("E", size, val.length())
                raise ParseException("Invalid substitution value size")
            sub_def.append(val)
            ofs += size
        debug("subs end at %s" % (hex(self.offset() + ofs)))
        return sub_def

    @memoize
    def length(self):
        ret = 0
        ofs = self.tag_and_children_length()
        debug("subs begin at %s" % (hex(self.offset() + ofs)))
        sub_count = self.unpack_dword(ofs)
        debug("count: %s" % (sub_count))
        ofs += 4
        ret = ofs
        for _ in xrange(sub_count):
            size = self.unpack_word(ofs)
            ret += size + 4
            ofs += 4
        debug("subs decl end at %s" % (hex(self.offset() + ofs)))
        debug("root end at %s"  % (hex(self.offset() + ret)))
        return ret


class VariantTypeNode(BXmlNode):
    """

    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("VariantTypeNode at %s." % (hex(offset)))
        super(VariantTypeNode, self).__init__(buf, offset, chunk, parent)
        self._length = length

    def __repr__(self):
        return "%s(buf=%r, offset=%s, chunk=%r)" % \
            (self.__class__.__name__, self._buf, hex(self.offset()),
             self._chunk)

    def __str__(self):
        return "%s(offset=%s, length=%s, string=%s)" % \
            (self.__class__.__name__, hex(self.offset()),
             hex(self.length()), self.string())

    def xml(self):
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
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(NullTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)

    def xml(self):
        return ""

    def template_format(self):
        return self.xml([])

    def string(self):
        return "NULL"

    def tag_length(self):
        return self._length or 0


class WstringTypeNode(VariantTypeNode):
    """
    Variant ttype 0x01.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(WstringTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        if self._length is None:
            self.declare_field("word",    "string_length", 0x0)
            self.declare_field("wstring", "string",
                               length=(self.string_length()))
        else:
            self.declare_field("wstring", "string", 0x0,
                               length=(self._length / 2))

    def xml(self):
        # ensure this is a str, not unicode
        try:
            return str(self.string())
        except UnicodeEncodeError:
            try:
                return self.string().encode("ascii", "xmlcharrefreplace")
            except (UnicodeEncodeError, UnicodeDecodeError) as e:
                debug("E", "%r" % (self), e)
                return str(self.string())

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        if self._length is None:
            return (2 + (self.string_length() * 2))
        return self._length


class StringTypeNode(VariantTypeNode):
    """
    Variant type 0x02.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(StringTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        if self._length is None:
            self.declare_field("word",   "string_length", 0x0)
            self.declare_field("string", "string",
                               length=(self.string_length()))
        else:
            self.declare_field("string", "string", 0x0, length=self._length)

    def xml(self):
        return str(self.string())

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        if self._length is None:
            return (2 + (self.string_length()))
        return self._length


class SignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x03.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedByteTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("int8", "byte", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class UnsignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x04.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedByteTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                   length=length)
        self.declare_field("byte", "byte", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class SignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x05.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedWordTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("int16", "word", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class UnsignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x06.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedWordTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                   length=length)
        self.declare_field("word", "word", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class SignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x07.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedDwordTypeNode, self).__init__(buf, offset, chunk,
                                                  parent, length=length)
        self.declare_field("int32", "dword", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class UnsignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x08.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedDwordTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                    length=length)
        self.declare_field("dword", "dword", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class SignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x09.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SignedQwordTypeNode, self).__init__(buf, offset, chunk,
                                                  parent, length=length)
        self.declare_field("int64", "qword", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class UnsignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x0A.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(UnsignedQwordTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                    length=length)
        self.declare_field("qword", "qword", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class FloatTypeNode(VariantTypeNode):
    """
    Variant type 0x0B.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(FloatTypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("float", "float", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 4

    def string(self):
        return str(self.float())


class DoubleTypeNode(VariantTypeNode):
    """
    Variant type 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(DoubleTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        self.declare_field("double", "double", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 8

    def string(self):
        return str(self.double())


class BooleanTypeNode(VariantTypeNode):
    """
    Variant type 0x0D.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(BooleanTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        self.declare_field("int32", "int32", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

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
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(BinaryTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        if self._length is None:
            self.declare_field("dword", "size", 0x0)
            self.declare_field("binary", "binary", length=self.size())
        else:
            self.declare_field("binary", "binary", 0x0, length=self._length)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        if self._length is None:
            return (4 + self.size())
        return self._length

    def string(self):
        return base64.b64encode(self.binary())


class GuidTypeNode(VariantTypeNode):
    """
    Variant type 0x0F.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(GuidTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        self.declare_field("guid", "guid", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 16

    def string(self):
        return "{%s}" % (self.guid())


class SizeTypeNode(VariantTypeNode):
    """
    Variant type 0x10.

    Note: Assuming sizeof(size_t) == 0x8.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SizeTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        if self._length == 0x4:
            self.declare_field("dword", "num", 0x0)
        elif self._length == 0x8:
            self.declare_field("qword", "num", 0x0)
        else:
            self.declare_field("qword", "num", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        if self._length is None:
            return 8
        return self._length

    def string(self):
        return str(self.num())


class FiletimeTypeNode(VariantTypeNode):
    """
    Variant type 0x11.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(FiletimeTypeNode, self).__init__(buf, offset, chunk,
                                               parent, length=length)
        self.declare_field("filetime", "filetime", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 8

    def string(self):
        return self.filetime().isoformat("T") + "Z"


class SystemtimeTypeNode(VariantTypeNode):
    """
    Variant type 0x12.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SystemtimeTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("systemtime", "systemtime", 0x0)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 16

    def string(self):
        return self.systemtime().isoformat("T") + "Z"


class SIDTypeNode(VariantTypeNode):
    """
    Variant type 0x13.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(SIDTypeNode, self).__init__(buf, offset, chunk,
                                          parent, length=length)
        self.declare_field("byte",  "version", 0x0)
        self.declare_field("byte",  "num_elements")
        self.declare_field("dword_be", "id_high")
        self.declare_field("word_be",  "id_low")

    @memoize
    def elements(self):
        ret = []
        for i in xrange(self.num_elements()):
            ret.append(self.unpack_dword(self.current_field_offset() + 4 * i))
        return ret

    @memoize
    def id(self):
        ret = "S-%d-%d" % \
            (self.version(), (self.id_high() << 16) ^ self.id_low())
        for elem in self.elements():
            ret += "-%d" % (elem)
        return ret

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 8 + 4 * self.num_elements()

    def string(self):
        return self.id()


class Hex32TypeNode(VariantTypeNode):
    """
    Variant type 0x14.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(Hex32TypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x4)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 4

    def string(self):
        ret = "0x"
        for c in self.hex()[::-1]:
            ret += "%02x" % (ord(c))
        return ret


class Hex64TypeNode(VariantTypeNode):
    """
    Variant type 0x15.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(Hex64TypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x8)

    def xml(self):
        return self.string()

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        return 8

    def string(self):
        ret = "0x"
        for c in self.hex()[::-1]:
            ret += "%02x" % (ord(c))
        return ret


class BXmlTypeNode(VariantTypeNode):
    """
    Variant type 0x21.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(BXmlTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        self._root = RootNode(buf, offset, chunk, self)

    def xml(self):
        return self._root.xml([])

    def template_format(self):
        # TODO(wb): this may be incorrect. self._root.template_format()?
        return self.xml([])

    def tag_length(self):
        return self._length or self._root.length()

    def string(self):
        return str(self._root)


class WstringArrayTypeNode(VariantTypeNode):
    """
    Variant ttype 0x81.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        debug("%s at %s." % (self.__class__.__name__, hex(offset)))
        super(WstringArrayTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        if self._length is None:
            self.declare_field("word",   "binary_length", 0x0)
            self.declare_field("binary", "binary",
                               length=(self.binary_length()))
        else:
            self.declare_field("binary", "binary", 0x0,
                               length=(self._length))

    def xml(self):
        ret = ""
        bin = self.binary()
        strings = []
        for apart in bin.split("\x00\x00\x00"):
            for bpart in apart.split("\x00\x00"):
                if len(bpart) % 2 == 1:
                    strings.append(bpart + "\x00")
                else:
                    strings.append(bpart)
        if strings[-1].strip("\x00") == "":
            strings = strings[:-1]
        for (i, string) in enumerate(strings):
            ret += "[%d] %s\n" % (i, string.decode("utf-16"))
        return ret

    def template_format(self):
        return self.xml([])

    def tag_length(self):
        if self._length is None:
            return (2 + self.binary_length())
        return self._length

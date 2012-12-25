from BinaryParser import *

class BXmlNode(Block):
    def __init__(self, buf, offset, chunk, parent):
        debug("BXmlNode at %s." % (hex(offset)))
        super(BXmlNode, self).__init__(buf, offset)
        self._chunk = chunk
        self._parent = parent

        self._dispatch_table = [
            Node0x00,
            Node0x01,
            Node0x02,
            Node0x03,
            Node0x04,
            Node0x05,
            Node0x06,
            Node0x07,
            Node0x08,
            Node0x09,
            Node0x0A,
            Node0x0B,
            Node0x0C,
            Node0x0D,
            Node0x0E,
            Node0x0F,
            ]



    def __repr__(self):
        return "BXmlNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "BXmlNode(offset=%s)" % (hex(self._offset))

    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for %r") % (self)

    def tag_length(self):
        """
        This method must be implemented and overridden for all BXmlNodes.
        @return An integer specifying the length of this tag, not including
          its children.
        """
        raise NotImplementedError("tag_length not implemented for %r") % \
            (self)

    def children(self):
        """
        @return A list containing all of the children BXmlNodes.
        """
        ret = []
        ofs = self.tag_length()
        while True:
            token = self.unpack_byte(ofs)
            if token == 0x00:
                break
            try:
                HandlerNodeClass = self._dispatch_table[token]
            except IndexError:
                child = HandlerNodeClass(self._buf, ofs, self._chunk, self)
            ret.append(child)
            ofs += child.length()
        return ret

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
        return "BXmlNode(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "BXmlNode(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        return self.string()
    
    def tag_length(self):
        return (self.string_length() * 2) + 8


class Node0x00(BXmlNode):
    """
    The binary XML node for the system token 0x00.
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

class Node0x01(BXmlNode):
    """
    The binary XML node for the system token 0x01.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x01 at %s." % (hex(offset)))
        super(Node0x01, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x01(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x01(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x01")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x01")


class Node0x02(BXmlNode):
    """
    The binary XML node for the system token 0x02.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x02 at %s." % (hex(offset)))
        super(Node0x02, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x02(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x02(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x02")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x02")


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


class Node0x04(BXmlNode):
    """
    The binary XML node for the system token 0x04.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x04 at %s." % (hex(offset)))
        super(Node0x04, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x04(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x04(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x04")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x04")


class Node0x05(BXmlNode):
    """
    The binary XML node for the system token 0x05.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x05 at %s." % (hex(offset)))
        super(Node0x05, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x05(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x05(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x05")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x05")


class Node0x06(BXmlNode):
    """
    The binary XML node for the system token 0x06.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x06 at %s." % (hex(offset)))
        super(Node0x06, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x06(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x06(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x06")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x06")


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


class Node0x0D(BXmlNode):
    """
    The binary XML node for the system token 0x0D.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x0D at %s." % (hex(offset)))
        super(Node0x0D, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x0D(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x0D(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x0D")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x0D")


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


class Node0x0F(BXmlNode):
    """
    The binary XML node for the system token 0x0F.
    """
    def __init__(self, buf, offset, chunk, parent):
        debug("Node0x0F at %s." % (hex(offset)))
        super(Node0x0F, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "Node0x0F(buf=%r, offset=%r, chunk=%r, parent=%r)" % \
            (self._buf, self._offset, self._chunk, self._parent)

    def __str__(self):
        return "Node0x0F(offset=%s)" % (hex(self._offset))
    
    def __xml__(self):
        raise NotImplementedError("__xml__ not implemented for Node0x0F")
    
    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for Node0x0F")



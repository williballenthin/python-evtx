#!/bin/python

#    This file is part of python-evtx.
#
#   Copyright 2012 Will Ballenthin <william.ballenthin@mandiant.com>
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
#   Version v.0.0.1

import struct, time, array, sys, cPickle, re, os, calendar
from datetime import datetime
import types

verbose = False

def debug(message):
    global verbose
    if verbose:
        print "# [d] %s" % (message)

def warning(message):
    print "# [w] %s" % (message)

def info(message):
    print "# [i] %s" % (message)

def error(message):
    print "# [e] %s" % (message)
    sys.exit(-1)

def align(offset, alignment):
    """
    Return the offset aligned to the nearest greater given alignment
    Arguments:
    - `offset`: An integer
    - `alignment`: An integer
    """
    if offset % alignment == 0:
        return offset
        return offset + (alignment - (offset % alignment))

def dosdate(dosdate, dostime):
    """
    `dosdate`: 2 bytes, little endian.
    `dostime`: 2 bytes, little endian.
    returns: datetime.datetime or datetime.datetime.min on error
    """
    try:
        t  = ord(dosdate[1]) << 8
        t |= ord(dosdate[0])
        day   = t & 0b0000000000011111
        month = (t & 0b0000000111100000) >> 5
        year  = (t & 0b1111111000000000) >> 9
        year += 1980
        
        t  = ord(dostime[1]) << 8
        t |= ord(dostime[0])
        sec     = t & 0b0000000000011111
        sec    *= 2
        minute  = (t & 0b0000011111100000) >> 5
        hour    = (t & 0b1111100000000000) >> 11

        return datetime.datetime(year, month, day, hour, minute, sec)
    except:
        return datetime.datetime.min

def parse_windows_timestamp(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)

class BinaryParserException(Exception):
    """
    Base Exception class for binary parsing.
    """    
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(BinaryParserException, self).__init__()
        self._value = value

    def __str__(self):
        return "Binary Parser Exception: %s" % (self._value)

class ParseException(BinaryParserException):
    """
    An exception to be thrown during binary parsing, such as 
    when an invalid header is encountered.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(ParseException, self).__init__(value)

    def __str__(self):
        return "Parse Exception(%s)" % (self._value)

class OverrunBufferException(ParseException):
    def __init__(self, readOffs, bufLen):
        tvalue = "read: %s, buffer length: %s" % (hex(readOffs), hex(bufLen))
        super(ParseException, self).__init__(tvalue)

    def __str__(self):
        return "Tried to parse beyond the end of the file (%s)" % \
            (self._value)

class Block(object):
    """ 
    Base class for structure blocks in binary parsing.
    A block is associated with a offset into a byte-string.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing stuff to parse.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        self._buf = buf
        self._offset = offset
        self._parent = parent
        self._implicit_offset = 0

    def __unicode__(self):
        return u"BLOCK @ %s." % (hex(self.offset()))

    def __str__(self):
        return str(unicode(self))

    def declare_field(self, type, name, offset=None, length=None):
        """
        Declaratively add fields to this block.
        This method will dynamically add corresponding offset and unpacker methods
        to this block.
        Arguments:
        - `type`: A string. Should be one of the unpack_* types.
        - `name`: A string. 
        - `offset`: A number.
        - `length`: (Optional) A number.
        """
        if offset == None:
            offset = self._implicit_offset
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset)
        elif length == None:
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset)
        else:
            def handler():
                f = getattr(self, "unpack_" + type)
                return f(offset, length)

        setattr(self, name, handler)
        setattr(self, "_off_" + name, offset)
        try:
            debug("(%s) %s\t@ %s\t: %s" % (type.upper(), 
                                           name, 
                                           hex(self.absolute_offset(offset)),
                                           str(handler())[:0x20]))
        except ValueError: # invalid Windows timestamp
            debug("(%s) %s\t@ %s\t: %s" % (type.upper(), 
                                           name, 
                                           hex(self.absolute_offset(offset)),
                                           "<<error>>"))
        if type == "byte":
            self._implicit_offset = offset + 1
        elif type == "word":
            self._implicit_offset = offset + 2
        elif type == "dword":
            self._implicit_offset = offset + 4
        elif type == "qword":
            self._implicit_offset = offset + 8
        elif type == "int":
            self._implicit_offset = offset + 4
        elif type == "dosdate":
            self._implicit_offset = offset + 4
        elif type == "windows_timestamp":
            self._implicit_offset = offset + 8
        elif type == "binary":
            self._implicit_offset = offset + length
        elif type == "string" and length != None:
            self._implicit_offset = offset + length
        elif type == "wstring" and length != None:
            self._implicit_offset = offset + (2 * length)
        elif "string" in type and length == None:
            raise ParseException("Implicit offset not supported for dynamic length strings")
        else:
            raise ParseException("Implicit offset not supported for type: " + type)            

    def current_field_offset(self):
        return self._implicit_offset

    def unpack_byte(self, offset):
        """
        Returns a little-endian unsigned byte from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<B", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_word(self, offset):
        """
        Returns a little-endian WORD (2 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<H", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def pack_word(self, offset, word):
        """
        Applies the little-endian WORD (2 bytes) to the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `word`: The data to apply.
        """
        o = self._offset + offset
        return struct.pack_into("<H", self._buf, o, word)

    def unpack_dword(self, offset):
        """
        Returns a little-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<I", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int(self, offset):
        """
        Returns a little-endian signed integer (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<i", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_qword(self, offset):
        """
        Returns a little-endian QWORD (8 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<Q", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_binary(self, offset, length=False):
        """
        Returns raw binary data from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the binary blob. If zero, the empty string
            zero length is returned.
        Throws:
        - `OverrunBufferException`
        """
        if not length:
            return ""
        o = self._offset + offset
        try:
            return struct.unpack_from("<%ds" % (length), self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_string(self, offset, length):
        """
        Returns a string from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        Throws:
        - `OverrunBufferException`
        """
        return self.unpack_binary(offset, length)

    def unpack_wstring(self, offset, length):
        """
        Returns a string from the relative offset with the given length,
        where each character is a wchar (2 bytes)
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        Throws:
        - `UnicodeDecodeError`
        """
        try:
            return self._buf[self._offset + offset:self._offset + offset + \
                             2 * length].tostring().decode("utf16")
        except AttributeError: # already a 'str' ?
            return self._buf[self._offset + offset:self._offset + offset + \
                             2 * length].decode("utf16")

    def unpack_dosdate(self, offset):
        """
        Returns a datetime from the DOSDATE and DOSTIME starting at 
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        try:
            o = self._offset + offset
            return dosdate(self._buf[o:o + 2], self._buf[o + 2:o + 4])
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_windows_timestamp(self, offset):
        """
        Returns a datetime from the QWORD Windows timestamp starting at
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        return parse_windows_timestamp(self.unpack_qword(offset))

    def absolute_offset(self, offset):
        """
        Get the absolute offset from an offset relative to this block
        Arguments:
        - `offset`: The relative offset into this block.
        """
        return self._offset + offset

    def parent(self):
        """
        Get the parent block. See the class documentation for what 
          the parent link is.
        """
        return self._parent

    def offset(self):
        """
        Equivalent to self.absolute_offset(0x0), which is the starting 
          offset of this block.
        """
        return self._offset

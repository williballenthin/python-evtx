import struct

import pytest

import Evtx.Nodes as e_nodes


def value(type_, data, length=None):
    return e_nodes.get_variant_value(data, 0, None, None, type_, length=len(data) if length is None else length)


def test_unsigned_qword_array():
    node = value(0x8A, struct.pack("<3Q", 1, 2, 2**64 - 1))
    assert node.string() == "<string>1</string>\n<string>2</string>\n<string>18446744073709551615</string>\n"
    assert node.length() == 24


def test_other_fixed_width_arrays():
    assert value(0x84, bytes([0xFF, 0x01])).string() == "<string>255</string>\n<string>1</string>\n"
    assert value(0x83, bytes([0xFF, 0x01])).string() == "<string>-1</string>\n<string>1</string>\n"
    assert value(0x88, struct.pack("<2I", 9, 10)).string() == "<string>9</string>\n<string>10</string>\n"
    assert value(0x95, struct.pack("<Q", 0x0706050403020100)).string() == "<string>0x0706050403020100</string>\n"


def test_empty_array():
    assert value(0x8A, b"").string() == ""


def test_partial_element_raises():
    with pytest.raises(e_nodes.ParseException):
        value(0x8A, bytes(12))


def test_unknown_type_raises_not_implemented():
    with pytest.raises(NotImplementedError):
        value(0x93, bytes(8))

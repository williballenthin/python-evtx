from fixtures import *

import Evtx.Evtx as evtx


def test_file_header(system):
    '''
    regression test parsing some known fields in the file header.

    Args:
      system (bytes): the system.evtx test file contents. pytest fixture.
    '''
    fh = evtx.FileHeader(system, 0x0)

    # collected empirically
    assert fh.magic() == 'ElfFile\x00'
    assert fh.major_version() == 0x3
    assert fh.minor_version() == 0x1
    assert fh.flags() == 0x1
    assert fh.is_dirty() is True
    assert fh.is_full() is False
    assert fh.current_chunk_number() == 0x8
    assert fh.chunk_count() == 0x9
    assert fh.oldest_chunk() == 0x0
    assert fh.next_record_number() == 0x34d8
    assert fh.checksum() == 0x41b4b1ec
    assert fh.calculate_checksum() == fh.checksum()


def test_file_header2(security):
    '''
    regression test parsing some known fields in the file header.

    Args:
      security (bytes): the security.evtx test file contents. pytest fixture.
    '''
    fh = evtx.FileHeader(security, 0x0)

    # collected empirically
    assert fh.magic() == 'ElfFile\x00'
    assert fh.major_version() == 0x3
    assert fh.minor_version() == 0x1
    assert fh.flags() == 0x1
    assert fh.is_dirty() is True
    assert fh.is_full() is False
    assert fh.current_chunk_number() == 0x19
    assert fh.chunk_count() == 0x1a
    assert fh.oldest_chunk() == 0x0
    assert fh.next_record_number() == 0x8b2
    assert fh.checksum() == 0x3f6e33d5
    assert fh.calculate_checksum() == fh.checksum()

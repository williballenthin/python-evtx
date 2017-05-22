from fixtures import *

import Evtx.Evtx as evtx


EMPTY_MAGIC = '\x00' * 0x8


def test_chunks(system):
    '''
    regression test parsing some known fields in the file chunks.

    Args:
      system (bytes): the system.evtx test file contents. pytest fixture.
    '''
    fh = evtx.FileHeader(system, 0x0)

    expecteds = [
        {'start_file': 1,    'end_file': 153,  'start_log': 12049, 'end_log': 12201},
        {'start_file': 154,  'end_file': 336,  'start_log': 12202, 'end_log': 12384},
        {'start_file': 337,  'end_file': 526,  'start_log': 12385, 'end_log': 12574},
        {'start_file': 527,  'end_file': 708,  'start_log': 12575, 'end_log': 12756},
        {'start_file': 709,  'end_file': 882,  'start_log': 12757, 'end_log': 12930},
        {'start_file': 883,  'end_file': 1059, 'start_log': 12931, 'end_log': 13107},
        {'start_file': 1060, 'end_file': 1241, 'start_log': 13108, 'end_log': 13289},
        {'start_file': 1242, 'end_file': 1424, 'start_log': 13290, 'end_log': 13472},
        {'start_file': 1425, 'end_file': 1601, 'start_log': 13473, 'end_log': 13649},
    ]

    for i, chunk in enumerate(fh.chunks()):
        # collected empirically
        if i < 9:
            assert chunk.check_magic() is True
            assert chunk.calculate_header_checksum() == chunk.header_checksum()
            assert chunk.calculate_data_checksum() == chunk.data_checksum()

            expected = expecteds[i]
            assert chunk.file_first_record_number() == expected['start_file']
            assert chunk.file_last_record_number() == expected['end_file']
            assert chunk.log_first_record_number() == expected['start_log']
            assert chunk.log_last_record_number() == expected['end_log']

        else:
            assert chunk.check_magic() is False
            assert chunk.magic() == EMPTY_MAGIC

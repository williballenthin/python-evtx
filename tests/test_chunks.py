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

    # collected empirically
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
            assert chunk.magic() == 'ElfChnk\x00'
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


def test_chunks2(security):
    '''
    regression test parsing some known fields in the file chunks.

    Args:
      security (bytes): the security.evtx test file contents. pytest fixture.
    '''
    fh = evtx.FileHeader(security, 0x0)

    # collected empirically
    expecteds = [
        {'start_file': 1,    'end_file': 91,   'start_log': 1,    'end_log': 91},
        {'start_file': 92,   'end_file': 177,  'start_log': 92,   'end_log': 177},
        {'start_file': 178,  'end_file': 260,  'start_log': 178,  'end_log': 260},
        {'start_file': 261,  'end_file': 349,  'start_log': 261,  'end_log': 349},
        {'start_file': 350,  'end_file': 441,  'start_log': 350,  'end_log': 441},
        {'start_file': 442,  'end_file': 530,  'start_log': 442,  'end_log': 530},
        {'start_file': 531,  'end_file': 622,  'start_log': 531,  'end_log': 622},
        {'start_file': 623,  'end_file': 711,  'start_log': 623,  'end_log': 711},
        {'start_file': 712,  'end_file': 802,  'start_log': 712,  'end_log': 802},
        {'start_file': 803,  'end_file': 888,  'start_log': 803,  'end_log': 888},
        {'start_file': 889,  'end_file': 976,  'start_log': 889,  'end_log': 976},
        {'start_file': 977,  'end_file': 1063, 'start_log': 977,  'end_log': 1063},
        {'start_file': 1064, 'end_file': 1148, 'start_log': 1064, 'end_log': 1148},
        {'start_file': 1149, 'end_file': 1239, 'start_log': 1149, 'end_log': 1239},
        {'start_file': 1240, 'end_file': 1327, 'start_log': 1240, 'end_log': 1327},
        {'start_file': 1328, 'end_file': 1414, 'start_log': 1328, 'end_log': 1414},
        {'start_file': 1415, 'end_file': 1501, 'start_log': 1415, 'end_log': 1501},
        {'start_file': 1502, 'end_file': 1587, 'start_log': 1502, 'end_log': 1587},
        {'start_file': 1588, 'end_file': 1682, 'start_log': 1588, 'end_log': 1682},
        {'start_file': 1683, 'end_file': 1766, 'start_log': 1683, 'end_log': 1766},
        {'start_file': 1767, 'end_file': 1847, 'start_log': 1767, 'end_log': 1847},
        {'start_file': 1848, 'end_file': 1942, 'start_log': 1848, 'end_log': 1942},
        {'start_file': 1943, 'end_file': 2027, 'start_log': 1943, 'end_log': 2027},
        {'start_file': 2028, 'end_file': 2109, 'start_log': 2028, 'end_log': 2109},
        {'start_file': 2110, 'end_file': 2201, 'start_log': 2110, 'end_log': 2201},
        {'start_file': 2202, 'end_file': 2261, 'start_log': 2202, 'end_log': 2261},
    ]

    for i, chunk in enumerate(fh.chunks()):
        # collected empirically
        if i < 26:
            assert chunk.check_magic() is True
            assert chunk.magic() == 'ElfChnk\x00'
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

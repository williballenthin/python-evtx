import os
import pytest

import Evtx.Evtx as evtx

from fixtures import *


def get_record_by_num(log, record_num):
    for record in log.records():
        if record.record_num() == record_num:
            return record
    raise KeyError(record_num)


def test_issue_43(data_path):
    '''
    regression test demonstrating issue 43.

    Args:
      data_path (str): the file system path of the test directory.
    '''
    with evtx.Evtx(os.path.join(data_path, 'issue_43.evtx')) as log:
        bad_rec = get_record_by_num(log, 508)
        with pytest.raises(UnicodeDecodeError):
            _ = bad_rec.xml()


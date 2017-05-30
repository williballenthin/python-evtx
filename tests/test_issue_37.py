import Evtx.Evtx as evtx

from fixtures import *


def test_render_records(data_path):
    '''
    regression test demonstrating issue 37.

    Args:
      data_path (str): the file system path of the test directory.
    '''
    with evtx.Evtx(os.path.join(data_path, 'dns_log_malformed.evtx')) as log:
        for chunk in log.chunks():
            for record in chunk.records():
                assert record.xml() is not None

import os
import pytest

import Evtx.Evtx as evtx

from fixtures import *



def one(iterable):
    '''
    fetch a single element from the given iterable.

    Args:
      iterable (iterable): a sequence of things.

    Returns:
      object: the first thing in the sequence.
    '''
    for i in iterable:
        return i


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))


def test_hex64_value(data_path):
    '''
    regression test demonstrating issue 38.

    Args:
      data_path (str): the file system path of the test directory.
    '''
    with evtx.Evtx(os.path.join(data_path, 'issue_38.evtx')) as log:
        for chunk in log.chunks():
            record = one(chunk.records())
            event_data = get_child(record.lxml(), 'EventData')
            for data in event_data:
                if data.get('Name') != 'SubjectLogonId':
                    continue

                assert data.text == '0x000000000019d3af'




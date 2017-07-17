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


def get_children(node, tags, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    for tag in tags:
        node = get_child(node, tag, ns=ns)
    return node


def test_systemtime(data_path):
    '''
    regression test demonstrating issue 39.

    Args:
      data_path (str): the file system path of the test directory.
    '''
    with evtx.Evtx(os.path.join(data_path, 'issue_39.evtx')) as log:
        for record in log.records():
            if record.record_num() != 129:
                continue

            time_created = get_children(record.lxml(), ['System', 'TimeCreated'])
            assert time_created.get('SystemTime') == '2017-04-21 07:41:17.003393'


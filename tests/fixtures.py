import os
import mmap
import os.path
import contextlib

import pytest


@pytest.fixture
def system_path():
    '''
    fetch the file system path of the system.evtx test file.

    Returns:
      str: the file system path of the test file.
    '''
    cd = os.path.dirname(__file__)
    datadir = os.path.join(cd, 'data')
    systempath = os.path.join(datadir, 'system.evtx')
    return systempath


@pytest.yield_fixture
def system():
    '''
    yields the contents of the system.evtx test file.
    the returned value is a memory map of the contents,
     so it acts pretty much like a byte string.

    Returns:
      mmap.mmap: the contents of the test file.
    '''
    p = system_path()
    with open(p, 'rb') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            yield buf

import os
import mmap
import os.path
import contextlib

import pytest


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


def security_path():
    '''
    fetch the file system path of the security.evtx test file.

    Returns:
      str: the file system path of the test file.
    '''
    cd = os.path.dirname(__file__)
    datadir = os.path.join(cd, 'data')
    secpath = os.path.join(datadir, 'security.evtx')
    return secpath


@pytest.yield_fixture
def security():
    '''
    yields the contents of the security.evtx test file.
    the returned value is a memory map of the contents,
     so it acts pretty much like a byte string.

    Returns:
      mmap.mmap: the contents of the test file.
    '''
    p = security_path()
    with open(p, 'rb') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            yield buf


@pytest.fixture
def data_path():
    '''
    fetch the file system path of the directory containing test files.

    Returns:
      str: the file system path of the test directory.
    '''
    cd = os.path.dirname(__file__)
    datadir = os.path.join(cd, 'data')
    return datadir


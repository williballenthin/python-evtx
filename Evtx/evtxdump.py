import sys
import binascii
import mmap
import contextlib
from Evtx import *


def main():
    with open(sys.argv[1], 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, 
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            print "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>"
            print "<Events>"
            for chunk in fh.chunks():
                for record in chunk.records():
                    print record.root().xml([])
            print "</Events>"            

if __name__ == "__main__":
    main()


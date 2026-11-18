import struct
import threading

import Evtx.Evtx as evtx


def _finishes_within(func, timeout=10):
    """Run func() in a daemon thread and report whether it returned in time.

    A cyclic offset chain makes the unpatched loader spin forever; the daemon
    thread is abandoned when the test process exits, so a hang shows up as a
    failed assertion rather than wedging the whole suite.
    """
    done = threading.Event()

    def work():
        func()
        done.set()

    threading.Thread(target=work, daemon=True).start()
    done.wait(timeout)
    return done.is_set()


def _chunk_with_cyclic_strings():
    """A single 64 KB chunk whose first string-hash bucket points at a cyclic
    NameStringNode chain: A.next_offset -> B, B.next_offset -> A."""
    buf = bytearray(0x10000)
    buf[0:8] = b"ElfChnk\x00"
    a, b = 0x200, 0x210
    struct.pack_into("<I", buf, 0x80, a)  # string hash bucket[0] -> A
    struct.pack_into("<I", buf, a, b)  # A.next_offset -> B
    struct.pack_into("<H", buf, a + 6, 0)  # A.string_length = 0
    struct.pack_into("<I", buf, b, a)  # B.next_offset -> A  (A <-> B)
    struct.pack_into("<H", buf, b + 6, 0)  # B.string_length = 0
    return bytes(buf)


def _chunk_with_cyclic_templates():
    """A single 64 KB chunk whose first template bucket points at a cyclic
    TemplateNode chain: T1.next_offset -> T2, T2.next_offset -> T1. Each
    template satisfies the token (0x0C) and self-pointer checks so the loader
    actually follows next_offset."""
    buf = bytearray(0x10000)
    buf[0:8] = b"ElfChnk\x00"
    # keep the templates (and the token/self-pointer bytes they carry at
    # ofs-10 / ofs-4) above the chunk's string- and template-bucket tables,
    # which end at 0x200, so the fixture only exercises the cyclic chain.
    t1, t2 = 0x400, 0x500
    struct.pack_into("<I", buf, 0x180, t1)  # template bucket[0] -> T1
    for this, nxt in ((t1, t2), (t2, t1)):
        buf[this - 10] = 0x0C  # token checked at ofs-10
        struct.pack_into("<I", buf, this - 4, this)  # self-pointer checked at ofs-4
        struct.pack_into("<I", buf, this, nxt)  # next_offset -> other
        struct.pack_into("<I", buf, this + 0x14, 0)  # data_length = 0
    return bytes(buf)


def test_cyclic_string_offsets_terminate():
    """A cyclic NameStringNode chain must not make _load_strings loop forever."""
    buf = _chunk_with_cyclic_strings()
    result = {}

    def load():
        result["strings"] = evtx.ChunkHeader(buf, 0).strings()

    assert _finishes_within(load), "strings() did not terminate on a cyclic chain"
    assert set(result["strings"].keys()) == {0x200, 0x210}


def test_cyclic_template_offsets_terminate():
    """A cyclic TemplateNode chain must not make _load_templates loop forever."""
    buf = _chunk_with_cyclic_templates()
    result = {}

    def load():
        result["templates"] = evtx.ChunkHeader(buf, 0).templates()

    assert _finishes_within(load), "templates() did not terminate on a cyclic chain"
    assert set(result["templates"].keys()) == {0x400, 0x500}

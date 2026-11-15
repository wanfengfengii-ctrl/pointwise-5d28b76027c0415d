"""Independent reference verification for the restricted QPACK profile.

Everything in this module is written from scratch (its own prefix-integer /
string codecs, its own table model and its own encoder) and never imports
qcapture or wire, so agreement here is an independent cross-check rather than
shared code agreeing with itself.

Run:  python3 refchecks.py normal
"""
import gc
import random
import resource
import sys
from collections import deque

STATIC = {0: (b':authority', b''), 1: (b':path', b'/'),
          17: (b':method', b'GET'), 23: (b':scheme', b'https'),
          25: (b':status', b'200')}


class RefError(Exception):
    """The oracle itself rejects an operation (used to skip illegal random ops)."""


# --------------------------------------------------------------------- codecs
def vint(value, prefix, lead):
    """Independent prefix-integer encoder (lead carries the pattern bits)."""
    top = (1 << prefix) - 1
    if value < top:
        return bytes([lead | value])
    out = bytearray([lead | top])
    value -= top
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def vstr(data):
    """Non-Huffman string: 7-bit length prefix + raw bytes."""
    return vint(len(data), 7, 0) + data


# --------------------------------------------------------------------- oracle
class Oracle:
    """Standalone model of the same restricted profile, plus a wire encoder."""

    def __init__(self, maximum, max_blocked):
        self.maximum = maximum
        self.max_blocked = max_blocked
        self.m = maximum // 32
        self.f = 2 * self.m
        self.cap = 0
        self.tbl = deque()          # (seq, name, value, size), oldest first
        self.size = 0
        self.t = 0
        self.blocked = []           # [dict(sid, r, base, specs, refs)]
        self.events = []            # expected deliveries in acceptance order

    # table mechanics ---------------------------------------------------------
    def _protected(self):
        refs = set()
        for blk in self.blocked:
            refs.update(blk['refs'])
        return refs

    def _evict_for(self, entry_size):
        if entry_size > self.cap:
            raise RefError('entry exceeds capacity')
        protected = None
        while self.size + entry_size > self.cap:
            oldest = self.tbl[0]
            if protected is None:
                protected = self._protected()
            if oldest[0] in protected:
                raise RefError('eviction blocked by held reference')
            self.tbl.popleft()
            self.size -= oldest[3]

    def _insert(self, name, value):
        seq = self.t + 1
        entry_size = 32 + len(name) + len(value)
        self._evict_for(entry_size)
        self.tbl.append((seq, bytes(name), bytes(value), entry_size))
        self.size += entry_size
        self.t = seq
        self._unblock()

    def set_capacity(self, cap):
        if cap > self.maximum:
            raise RefError('capacity over maximum')
        protected = None
        while self.size > cap:
            oldest = self.tbl[0]
            if protected is None:
                protected = self._protected()
            if oldest[0] in protected:
                raise RefError('shrink blocked by held reference')
            self.tbl.popleft()
            self.size -= oldest[3]
        self.cap = cap
        return vint(cap, 5, 0x20)

    def insert_literal(self, name, value):
        seq = self.t + 1
        entry_size = 32 + len(name) + len(value)
        self._evict_for(entry_size)
        wire = vint(len(name), 5, 0x40) + name + vstr(value)
        self.tbl.append((seq, bytes(name), bytes(value), entry_size))
        self.size += entry_size
        self.t = seq
        self._unblock()
        return wire

    def insert_name_ref(self, static_flag, index, value):
        if static_flag:
            if index not in STATIC:
                raise RefError('bad static index')
            name = STATIC[index][0]
            lead = 0xC0
        else:
            if not 0 <= index < len(self.tbl):
                raise RefError('bad dynamic relative index')
            name = self.tbl[-1 - index][1]
            lead = 0x80
        seq = self.t + 1
        entry_size = 32 + len(name) + len(value)
        self._evict_for(entry_size)
        wire = vint(index, 6, lead) + vstr(value)
        self.tbl.append((seq, bytes(name), bytes(value), entry_size))
        self.size += entry_size
        self.t = seq
        self._unblock()
        return wire

    def duplicate(self, rel):
        if not 0 <= rel < len(self.tbl):
            raise RefError('bad duplicate relative index')
        source = self.tbl[-1 - rel]
        wire = vint(rel, 5, 0x00)
        self._insert(source[1], source[2])
        return wire

    # header blocks -----------------------------------------------------------
    def _encode_r(self, r):
        if r == 0:
            return b'\x00'
        # Inverse of the decoder's RFC 9204 E decoding: pick the unique E in
        # [1, F] that the decoder resolves back to r. Enumerating keeps the two
        # implementations genuinely independent.
        chosen = None
        for e in range(1, self.f + 1):
            v = self.t + self.m
            w = (v // self.f) * self.f
            cand = w + e - 1
            if cand > v:
                if cand <= self.f:
                    continue
                cand -= self.f
            if cand == r:
                chosen = e
                break
        if chosen is None:
            raise RefError('r not representable in current EIC window')
        return vint(chosen, 8, 0)

    def submit(self, sid, r, base, specs):
        """Build a block for specs; record oracle-side state. Returns bytes."""
        refs = set()
        max_ref = 0
        for spec in specs:
            if spec[0] in ('d', 'dn'):
                seq = spec[1]
                if r == 0 or seq <= 0 or seq > r:
                    raise RefError('dynamic ref outside R')
                if seq <= self.t and not self._in_table(seq):
                    raise RefError('ref to evicted entry')
                refs.add(seq)
                max_ref = max(max_ref, seq)
        if r == 0:
            if refs:
                raise RefError('R=0 with dynamic refs')
        elif max_ref != r:
            raise RefError('max ref must equal R')
        wire = self._encode_r(r)
        if base >= r:
            wire += vint(base - r, 7, 0)
        else:
            wire += vint(r - base - 1, 7, 0x80)
        for spec in specs:
            kind = spec[0]
            if kind == 'si':
                wire += vint(spec[1], 6, 0xC0)
            elif kind == 'sn':
                wire += vint(spec[1], 4, 0x40) + vstr(spec[2])
            elif kind == 'lit':
                wire += vint(len(spec[1]), 3, 0x20) + spec[1] + vstr(spec[2])
            elif kind == 'd':
                seq = spec[1]
                if seq <= base:
                    wire += vint(base - seq, 6, 0x80)
                else:
                    wire += vint(seq - base - 1, 4, 0x10)
            else:  # 'dn'
                seq, value = spec[1], spec[2]
                if seq <= base:
                    wire += vint(base - seq, 4, 0x40) + vstr(value)
                else:
                    wire += vint(seq - base - 1, 3, 0x00) + vstr(value)
        desc = {'sid': sid, 'r': r, 'base': base, 'specs': specs, 'refs': refs}
        if r > self.t:
            self.blocked.append(desc)
            return wire, []
        return wire, [(sid, self._render(desc))]

    def _in_table(self, seq):
        return bool(self.tbl) and self.tbl[0][0] <= seq <= self.tbl[-1][0]

    def _entry(self, seq):
        return self.tbl[seq - self.tbl[0][0]]

    def _render(self, desc):
        out = []
        for spec in desc['specs']:
            kind = spec[0]
            if kind == 'si':
                out.append(STATIC[spec[1]])
            elif kind == 'sn':
                out.append((STATIC[spec[1]][0], spec[2]))
            elif kind == 'lit':
                out.append((spec[1], spec[2]))
            elif kind == 'd':
                e = self._entry(spec[1])
                out.append((e[1], e[2]))
            else:
                out.append((self._entry(spec[1])[1], spec[2]))
        return out

    def _unblock(self):
        ready = []
        stay = []
        for desc in self.blocked:
            if desc['r'] <= self.t:
                ready.append((desc['sid'], self._render(desc)))
            else:
                stay.append(desc)
        self.blocked = stay
        self.events.extend(ready)

    def cancel(self, sid):
        self.blocked = [d for d in self.blocked if d['sid'] != sid]


# ----------------------------------------------------------------- test helper
def expect_value_error(label, fn):
    from qcapture import Decoder
    d = Decoder(128, 2)
    try:
        fn(d)
    except ValueError:
        pass
    else:
        raise AssertionError(label + ' should raise ValueError')
    # permanent failure: every later method must fail
    for call in (lambda: d.header(99, b'\x00\x00'),
                 lambda: d.feed_encoder(b''),
                 lambda: d.cancel(99),
                 lambda: d.finish()):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError(label + ' did not fail permanently')


def feed_split(decoder, blob, rng):
    """Feed blob through random chunk boundaries; 1/n runs are byte-by-byte."""
    out = []
    i = 0
    mode = rng.randrange(3)
    while i < len(blob):
        step = 1 if mode == 0 else rng.randrange(1, 5)
        out += decoder.feed_encoder(blob[i:i + step])
        i += step
    return out


# ------------------------------------------------------------- hand-built cases
def hand_cases():
    from qcapture import Decoder

    # 1. Contract worked sample, whole and byte-by-byte ---------------------
    inst = bytes.fromhex('3f6141780161')
    for cut in range(1, len(inst) + 1):
        d = Decoder(128, 2)
        assert d.header(0, bytes.fromhex('020080')) == []
        got, i = [], 0
        while i < len(inst):
            got += d.feed_encoder(inst[i:i + cut]); i += cut
        assert got == [(0, [(b'x', b'a')])], got
        assert d.finish() is None

    # 2. Mixed pre/post-base, static, literal block; duplicates; blocking ---
    d = Decoder(160, 3)
    o = Oracle(160, 3)
    cap = o.set_capacity(160)
    w1 = o.insert_literal(b'', b'')          # seq1, size 32
    w2 = o.insert_literal(b'', b'')          # seq2
    assert d.feed_encoder(cap + w1 + w2) == []
    block, immediate = o.submit(
        0, 4, 2,
        [('d', 1), ('dn', 2, b'zz'), ('d', 3), ('dn', 4, b'qq'),
         ('si', 17), ('lit', b'k', b'val')])
    assert immediate == []
    assert d.header(0, block) == []          # T=2 < R=4 -> blocked
    w3 = o.duplicate(0)                      # seq3 = copy of seq2
    w4 = o.duplicate(0)                      # seq4 = copy of seq3
    got = d.feed_encoder(w3 + w4)
    expect = [(0, [(b'', b''), (b'', b'zz'), (b'', b''), (b'', b'qq'),
                   (b':method', b'GET'), (b'k', b'val')])]
    assert got == expect, got
    assert o.events == expect
    assert d.finish() is None

    # 3. Multi-byte prefix integer split across chunks ----------------------
    d = Decoder(1024, 2)
    o = Oracle(1024, 2)
    blob = o.set_capacity(100)              # 5-bit prefix needs one continuation
    assert blob == bytes([0x3f, 0x45]) and len(blob) == 2
    assert d.feed_encoder(blob[:1]) == []   # partial, table untouched
    assert d.capacity == 0
    assert d.feed_encoder(blob[1:]) == []
    assert d.capacity == 100
    assert d.finish() is None

    # 4. R=0 static compatibility and rejection -----------------------------
    d = Decoder(128, 2)
    assert d.header(0, bytes.fromhex('0000d1d7c1')) == [
        (0, [(b':method', b'GET'), (b':scheme', b'https'), (b':path', b'/')])]
    expect_value_error('R=0 dynamic indexed',
                       lambda x: x.header(1, bytes.fromhex('000080')))
    expect_value_error('R=0 post-base',
                       lambda x: x.header(1, bytes.fromhex('000010')))

    # 5. Wrap-around Encoded Insert Count -----------------------------------
    d = Decoder(1024, 2)
    o = Oracle(1024, 2)
    d.feed_encoder(o.set_capacity(1024))
    blob = b''
    for _ in range(70):
        blob += o.insert_literal(b'', b'')  # size 32; 32 fit, rest evict
    assert d.feed_encoder(blob) == []
    assert o.t == 70 and len(d.table) == 32 and d.table[0].seq == 39
    block, immediate = o.submit(7, 39, 39, [('d', 39)])
    assert block == bytes.fromhex('280080'), block.hex()  # E=40, S=0 D=0
    assert d.header(7, block) == immediate == [(7, [(b'', b'')])]
    # bad wrap: E resolves to R=0 at T=0; and E > F
    expect_value_error('E resolving to zero',
                       lambda x: x.header(1, bytes.fromhex('010080')))
    expect_value_error('E greater than F',
                       lambda x: x.header(1, bytes.fromhex('410080')))

    # 6. Duplicate semantics and bounds -------------------------------------
    d = Decoder(128, 2)
    o = Oracle(128, 2)
    d.feed_encoder(o.set_capacity(128))
    d.feed_encoder(o.insert_literal(b'a', b'1'))   # seq1
    d.feed_encoder(o.insert_literal(b'b', b'2'))   # seq2
    assert d.feed_encoder(o.duplicate(1)) == []     # copy seq1 -> seq3
    assert [e.seq for e in d.table] == [1, 2, 3]
    assert (d.table[-1].name, d.table[-1].value) == (b'a', b'1')
    expect_value_error('dup rel out of range',
                       lambda x: x.feed_encoder(b'\x03'))
    empty = Decoder(128, 2)
    empty.feed_encoder(Oracle(128, 2).set_capacity(128))
    try:
        empty.feed_encoder(b'\x00')
    except ValueError:
        pass
    else:
        raise AssertionError('dup on empty table')

    # 7. Capacity shrink, grow, zero, over-maximum --------------------------
    d = Decoder(128, 2)
    o = Oracle(128, 2)
    d.feed_encoder(o.set_capacity(128))
    d.feed_encoder(o.insert_literal(b'n', b'v'))   # size 34 seq1
    d.feed_encoder(o.insert_literal(b'n', b'v'))   # seq2
    assert d.table_size == 68
    d.feed_encoder(o.set_capacity(40))             # evicts seq1
    assert [e.seq for e in d.table] == [2] and d.capacity == 40
    d.feed_encoder(o.set_capacity(0))
    assert len(d.table) == 0 and d.capacity == 0
    expect_value_error('insert at capacity 0',
                       lambda x: x.feed_encoder(bytes.fromhex('416e0176')))
    expect_value_error('capacity over maximum',
                       lambda x: x.feed_encoder(vint(129, 5, 0x20)))

    # 8. Insert with name reference -----------------------------------------
    d = Decoder(128, 2)
    o = Oracle(128, 2)
    d.feed_encoder(o.set_capacity(128))
    d.feed_encoder(o.insert_literal(b'name', b'v0'))      # seq1
    d.feed_encoder(o.insert_name_ref(False, 0, b'v1'))    # rel0 name
    assert d.table[-1].name == b'name' and d.table[-1].value == b'v1'
    d.feed_encoder(o.insert_name_ref(True, 25, b'201'))   # static :status
    assert d.table[-1].name == b':status'
    expect_value_error('unsupported static name index',
                       lambda x: x.feed_encoder(vint(2, 6, 0xC0) + vstr(b'x')))
    expect_value_error('dynamic name ref out of range',
                       lambda x: x.feed_encoder(vint(5, 6, 0x80) + vstr(b'x')))

    # 9. Eviction protection + cancel release -------------------------------
    illegal = vint(len(b'longer'), 5, 0x40) + b'longer' + vstr(b'xx')  # size 40
    d = Decoder(96, 2)
    o = Oracle(96, 2)
    d.feed_encoder(o.set_capacity(96))
    d.feed_encoder(o.insert_literal(b'', b''))     # seq1 size32
    block, _ = o.submit(0, 3, 3, [('d', 1), ('d', 3)])
    assert d.header(0, block) == []                # R=3 > T=1: blocked, holds seq1
    d.feed_encoder(o.insert_literal(b'', b''))     # seq2, 64 bytes used
    # next entry (size 40) would evict held seq1 -> hard failure
    try:
        d.feed_encoder(illegal)
    except ValueError:
        pass
    else:
        raise AssertionError('eviction past held reference must fail')
    assert d.failed
    # A fresh decoder shows cancel releases the same protection ------------
    d = Decoder(96, 2)
    o = Oracle(96, 2)
    d.feed_encoder(o.set_capacity(96))
    d.feed_encoder(o.insert_literal(b'', b''))     # seq1
    block, _ = o.submit(0, 3, 3, [('d', 1), ('d', 3)])
    d.header(0, block)
    assert d.cancel(0) == []
    o.cancel(0)
    # seq1 is no longer held: a size-40 entry now fits, and the next one
    # legally evicts seq1 (which the earlier blocking would have forbidden)
    d.feed_encoder(illegal)                        # seq2, 72 bytes used
    assert [e.seq for e in d.table] == [1, 2]
    d.feed_encoder(o.insert_literal(b'', b''))    # seq3 -> evicts seq1
    assert [e.seq for e in d.table] == [2, 3]
    # cancelled block is never delivered later
    assert d.feed_encoder(o.insert_literal(b'', b'')) == []

    # 10. Same-chunk unblock then eviction; per-instruction delivery --------
    d = Decoder(96, 3)
    o = Oracle(96, 3)
    d.feed_encoder(o.set_capacity(96))
    d.feed_encoder(o.insert_literal(b'', b''))        # seq1, size 32
    block, _ = o.submit(0, 3, 3, [('d', 1), ('d', 3)])
    assert d.header(0, block) == []                   # R=3 > T=1: blocked, holds seq1
    # seq2/seq3 fit without eviction; the 3rd insert unblocks sid0 (releasing
    # refs), and the 4th insert then legally evicts seq1 -- all in one chunk.
    # Bytes are hand-built: the oracle independently rejects eviction while it
    # still models the blocked block.
    small = vint(0, 5, 0x40) + vstr(b'')               # insert b''->b'', size 32
    got = d.feed_encoder(small + small + small + small)
    assert got == [(0, [(b'', b''), (b'', b'')])], got
    # the last insert must FIFO-evict both seq1 and seq2; seq3 (the unblocking
    # entry) survives, proving unblock happened before the eviction
    assert [e.seq for e in d.table] == [3, 4, 5] and d.table_size == 96
    # acceptance order across separate unblock points
    d = Decoder(128, 4)
    o = Oracle(128, 4)
    d.feed_encoder(o.set_capacity(128))
    b0, _ = o.submit(0, 2, 2, [('d', 2)])
    b1, _ = o.submit(1, 1, 1, [('d', 1)])
    assert d.header(0, b0) == [] and d.header(1, b1) == []
    first = d.feed_encoder(o.insert_literal(b'', b''))   # seq1 -> sid1
    assert first == [(1, [(b'', b'')])], first
    second = d.feed_encoder(o.insert_literal(b'', b''))  # seq2 -> sid0
    assert second == [(0, [(b'', b'')])], second
    assert d.finish() is None

    # 11. max_blocked --------------------------------------------------------
    d = Decoder(128, 2)
    o = Oracle(128, 2)
    d.feed_encoder(o.set_capacity(128))
    b0, _ = o.submit(0, 1, 1, [('d', 1)]); d.header(0, b0)
    b1, _ = o.submit(1, 2, 2, [('d', 2)]); d.header(1, b1)
    b2, _ = o.submit(2, 3, 3, [('d', 3)])
    try:
        d.header(2, b2)
    except ValueError:
        pass
    else:
        raise AssertionError('third blocked stream must exceed max_blocked')
    assert d.failed
    # permanent failure blocks later calls
    try:
        d.feed_encoder(b'')
    except ValueError:
        pass
    else:
        raise AssertionError('over-limit failure must be permanent')
    # an immediately satisfiable block still works while at the limit
    d2 = Decoder(128, 2)
    o2 = Oracle(128, 2)
    d2.feed_encoder(o2.set_capacity(128))
    d2.feed_encoder(o2.insert_literal(b'', b''))
    blk, imm = o2.submit(3, 1, 1, [('d', 1)])
    assert d2.header(3, blk) == imm
    assert not d2.blocked

    # 12. Truncation / Huffman / malformed blocks ---------------------------
    expect_value_error('truncated block prefix', lambda x: x.header(0, b'\x00'))
    expect_value_error('truncated field integer',
                       lambda x: x.header(0, b'\x00\x00\xff'))      # needs continuation
    expect_value_error('truncated literal value',
                       lambda x: x.header(0, b'\x00\x00\x50\x03ab'))  # 3 bytes, 2 given
    expect_value_error('truncated literal name bytes',
                       lambda x: x.header(0, b'\x00\x00\x22xyz'))   # len 2, 0 given
    expect_value_error('empty block', lambda x: x.header(0, b''))
    expect_value_error('huffman field string',
                       lambda x: x.header(0, b'\x00\x00\x50\x83abc'))
    expect_value_error('huffman encoder string',
                       lambda x: x.feed_encoder(b'\x60\x03abc'))
    expect_value_error('huffman literal name in block',
                       lambda x: x.header(0, b'\x00\x00\x28\x01k\x01v'))
    d = Decoder(128, 2)
    d.feed_encoder(b'\x3f')                       # partial set-capacity
    try:
        d.finish()
    except ValueError:
        pass
    else:
        raise AssertionError('finish with partial instruction must fail')
    assert d.failed

    # 13. finish lifecycle ---------------------------------------------------
    d = Decoder(128, 2)
    assert d.finish() is None
    assert d.finish() is None                     # repeat finish allowed
    for call in (lambda: d.header(0, b'\x00\x00'),
                 lambda: d.feed_encoder(b''),
                 lambda: d.cancel(0)):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError('call after finish must fail')

    # 14. Constructor / argument validation ---------------------------------
    for args in ((31, 1), (True, 1), (128, 0), (128, False), ('128', 1), (128, 1.0)):
        try:
            Decoder(*args)
        except ValueError:
            continue
        raise AssertionError('bad constructor args %r' % (args,))
    d = Decoder(128, 2)
    expect_value_error('bool stream id', lambda x: x.header(True, b'\x00\x00'))
    expect_value_error('non-bytes block', lambda x: x.header(0, '00'))
    expect_value_error('non-bytes chunk', lambda x: x.feed_encoder('00'))
    expect_value_error('negative sid cancel', lambda x: x.cancel(-1))
    d.header(5, b'\x00\x00')
    try:
        d.header(5, b'\x00\x00')                   # equal to last accepted id
    except ValueError:
        pass
    else:
        raise AssertionError('stream id must be strictly greater')
    assert d.failed
    expect_value_error('oversize block', lambda x: x.header(6, b'\x00' * 65537))
    expect_value_error('oversize chunk', lambda x: x.feed_encoder(b'\x00' * 32769))
    # integer overflow and seventh continuation byte
    expect_value_error('integer overflow',
                       lambda x: x.feed_encoder(b'\x1f\xff\xff\xff\xff\x7f'))
    expect_value_error('seventh continuation byte',
                       lambda x: x.feed_encoder(b'\x1f\x80\x80\x80\x80\x80\x80\x80\x01'))

    # 15. R mismatch, evicted-at-submit, raw bytes and duplicates -----------
    d = Decoder(160, 2)
    o = Oracle(160, 2)
    d.feed_encoder(o.set_capacity(160))
    d.feed_encoder(o.insert_literal(b'a', b'1'))   # seq1 size34
    d.feed_encoder(o.insert_literal(b'b', b'2'))   # seq2
    d.feed_encoder(o.insert_literal(b'c', b'3'))   # seq3
    d.feed_encoder(o.set_capacity(40))             # evicts seq1, seq2
    try:
        o.submit(0, 3, 3, [('d', 2), ('d', 3)])
    except RefError:
        pass
    else:
        raise AssertionError('oracle should reject evicted ref')
    expect_value_error('reference to evicted entry',
                       lambda x: x.header(0, bytes.fromhex('040082')))
    # raw binary value bytes, field order and repeated references preserved
    d = Decoder(160, 2)
    o = Oracle(160, 2)
    d.feed_encoder(o.set_capacity(160))
    d.feed_encoder(o.insert_literal(b'k', b'\x00\xff\x80raw'))  # seq1 size43
    block, imm = o.submit(0, 1, 1, [('d', 1), ('d', 1), ('lit', b'z', b'')])
    assert d.header(0, block) == [(0, [(b'k', b'\x00\xff\x80raw'),
                                       (b'k', b'\x00\xff\x80raw'),
                                       (b'z', b'')])]
    assert d.table_size == 32 + 1 + 6            # repeated refs cost nothing

    # 16. Cancel semantics ---------------------------------------------------
    d = Decoder(128, 2)
    assert d.cancel(123) == []                    # unknown id no-op
    d.header(7, b'\x00\x00')                      # last accepted = 7
    assert d.cancel(7) == []                      # completed id no-op
    d.header(8, b'\x00\x00')                      # acceptance still monotone

    # 17. Set Capacity never unblocks; inserts do ---------------------------
    d = Decoder(128, 2)
    o = Oracle(128, 2)
    d.feed_encoder(o.set_capacity(128))
    block, _ = o.submit(0, 1, 1, [('d', 1)])
    d.header(0, block)
    assert d.feed_encoder(o.set_capacity(64)) == []   # T unchanged, still blocked
    assert d.blocked and d.feed_encoder(o.insert_literal(b'', b'')) == [
        (0, [(b'', b'')])]

    print('HAND_CASES_OK')


# --------------------------------------------------------- randomized cross-check
def randomized_cases(seed=20261115, rounds=120):
    from qcapture import Decoder
    rng = random.Random(seed)

    def rb(lo, hi):
        return bytes(rng.randrange(256) for _ in range(rng.randrange(lo, hi)))

    for _ in range(rounds):
        maximum = rng.choice((64, 96, 128, 256, 512))
        mb = rng.randrange(1, 4)
        d = Decoder(maximum, mb)
        o = Oracle(maximum, mb)
        sid = 0
        finished = False
        for _ in range(rng.randrange(60, 140)):
            choice = rng.randrange(7)
            if choice == 0:                      # set capacity
                cap = rng.randrange(0, maximum + 1)
                try:
                    blob = o.set_capacity(cap)
                except RefError:
                    continue
                got = feed_split(d, blob, rng)
                assert got == o.events and not o.events
                o.events.clear()
                assert d.capacity == o.cap and d.table_size == o.size
            elif choice in (1, 2):               # inserts
                name, value = rb(0, 8), rb(0, 8)
                try:
                    if choice == 1:
                        blob = o.insert_literal(name, value)
                    elif o.tbl and rng.randrange(2):
                        blob = o.insert_name_ref(False, rng.randrange(len(o.tbl)), value)
                    else:
                        blob = o.insert_name_ref(True, rng.choice(list(STATIC)), value)
                except RefError:
                    continue
                got = feed_split(d, blob, rng)
                assert got == o.events, (got, o.events)
                o.events.clear()
                assert d.insert_count == o.t
                assert [e.seq for e in d.table] == [e[0] for e in o.tbl]
                assert d.table_size == o.size
            elif choice == 3 and o.tbl:          # duplicate
                rel = rng.randrange(len(o.tbl))
                try:
                    blob = o.duplicate(rel)
                except RefError:
                    continue
                got = feed_split(d, blob, rng)
                assert got == o.events
                o.events.clear()
            elif choice == 4:                    # submit header block
                sid += 2
                if rng.randrange(4) == 0 or o.t == 0:
                    specs = []
                    if rng.randrange(2):
                        specs.append(('si', rng.choice(list(STATIC))))
                    if rng.randrange(2):
                        specs.append(('lit', rb(0, 5), rb(0, 5)))
                    if not specs:
                        specs.append(('si', 17))
                    r, base = 0, 0
                else:
                    future = list(range(o.t + 1, o.t + 1 + mb + 1))
                    candidates = [e[0] for e in o.tbl] + future
                    r = rng.choice(candidates)
                    try:
                        o._encode_r(r)
                    except RefError:
                        continue
                    base = rng.randrange(0, r + 1)
                    specs = []
                    for _ in range(rng.randrange(1, 5)):
                        seq = rng.randrange(1, r + 1)
                        if seq <= o.t and not o._in_table(seq):
                            continue
                        kind = rng.choice(('d', 'dn'))
                        if kind == 'd':
                            specs.append(('d', seq))
                        else:
                            specs.append(('dn', seq, rb(0, 6)))
                    if not any(s[0] in ('d', 'dn') and s[1] == r for s in specs):
                        specs.append(('d', r))
                    if rng.randrange(2):
                        specs.insert(0, ('si', rng.choice(list(STATIC))))
                    if rng.randrange(2):
                        specs.append(('lit', rb(0, 4), rb(0, 4)))
                try:
                    block, expect_imm = o.submit(sid, r, base, specs)
                except RefError:
                    continue
                if len(o.blocked) > mb:          # oracle would exceed limit
                    o.blocked.pop()
                    try:
                        d.header(sid, block)
                    except ValueError:
                        assert d.failed
                        break
                    raise AssertionError('over-limit block should fail')
                got = d.header(sid, block)
                assert got == expect_imm, (got, expect_imm)
            elif choice == 5 and o.blocked:      # cancel
                victim = rng.choice(o.blocked)['sid']
                assert d.cancel(victim) == []
                o.cancel(victim)
            else:                                # drain everything then finish
                if not o.blocked:
                    assert d.finish() is None
                    finished = True
                    break
        if d.failed or finished:
            continue
        # drain any remaining blocked blocks with fresh inserts
        guard = 0
        while o.blocked and guard < 100:
            guard += 1
            try:
                blob = o.insert_literal(rb(0, 3), rb(0, 3))
            except RefError:
                blob = o.set_capacity(o.maximum)
            got = feed_split(d, blob, rng)
            assert got == o.events
            o.events.clear()
        assert not o.blocked and not d.blocked
        assert d.feed_encoder(b'') == [] and not d.encoder_buf
        assert d.finish() is None
    print('RANDOM_CASES_OK')


# ----------------------------------------------------- long-connection memory run
def long_connection():
    from qcapture import Decoder
    maximum, max_blocked = 96, 4
    d = Decoder(maximum, max_blocked)
    o = Oracle(maximum, max_blocked)
    d.feed_encoder(o.set_capacity(maximum))
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_table = peak_blocked = iterations = 0
    sid = 0
    sample = None
    rng = random.Random(7)
    for i in range(1, 20001):
        iterations = i
        name = bytes([65 + (i % 26)])
        value = b'v%05d' % (i % 100000,)
        blob = o.insert_literal(name, value)
        # split every feed across arbitrary 1..7 byte boundaries; events may
        # only appear when the final fragment completes the instruction
        got = []
        j = 0
        while j < len(blob):
            step = rng.randrange(1, 8)
            got += d.feed_encoder(blob[j:j + step])
            j += step
        assert got == o.events, (i, got, o.events)
        o.events.clear()
        peak_table = max(peak_table, len(d.table))
        peak_blocked = max(peak_blocked, len(d.blocked))
        if i % 37 == 0:
            sid += 2
            r = o.t + 2
            try:
                block, _ = o.submit(sid, r, r, [('d', r - 1), ('d', r)])
            except RefError:
                continue
            assert d.header(sid, block) == []
            assert len(d.blocked) <= max_blocked
        if i == 20000:
            # reconcile a real blocked block against the oracle field bytes
            sid += 2
            block, _ = o.submit(sid, o.t + 1, o.t + 1, [('d', o.t + 1)])
            d.header(sid, block)
            sample = (sid, block)
    # let the last blocked block resolve and reconcile exact field bytes
    blob = o.insert_literal(b'end', b'run')
    delivered = []
    j = 0
    while j < len(blob):
        delivered += d.feed_encoder(blob[j:j + 1]); j += 1
    assert delivered == o.events
    sid_sample, fields_sample = delivered[-1]
    assert sid_sample == sample[0]
    entry = o._entry(o.t)
    assert fields_sample == [(entry[1], entry[2])]
    # every earlier periodic block was delivered in acceptance order too
    assert [sid for sid, _ in delivered] == sorted(sid for sid, _ in delivered)
    gc.collect()
    rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    retained = sum(1 for _ in d.table)
    print('LONG_RUN iterations=%d peak_table_entries=%d (cap %d => max %d) '
          'peak_blocked=%d final_table=%d blocked=%d buf=%d '
          'rss_peak_kb_before=%d after=%d reconciled_sid=%d fields=%r'
          % (iterations, peak_table, maximum, maximum // 32, peak_blocked,
             retained, len(d.blocked), len(d.encoder_buf), rss0, rss1,
             sid_sample, fields_sample))
    assert peak_table <= maximum // 32
    assert peak_blocked <= max_blocked
    assert not d.blocked and not d.encoder_buf
    # no history is retained: only the bounded live table remains
    assert len(d.table) <= maximum // 32
    assert d.finish() is None
    print('LONG_CONNECTION_OK')


def main():
    hand_cases()
    randomized_cases()
    long_connection()
    print('REFCHECK_ALL_OK')


if __name__ == '__main__':
    main()

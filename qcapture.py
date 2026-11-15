"""Restricted QPACK capture profile for HTTP/3 retention.

This extends the original static-only Decoder with the constrained dynamic
profile described in CONTRACT.md: encoder instruction stream (insert with /
without name reference, duplicate, set capacity), blocked header blocks with
frozen Encoded Insert Count / Base, eviction protection held by blocked
blocks, cancellation and permanent failure. No QUIC/HTTP/3 frame handling and
no Huffman decoding.
"""
from collections import deque

from wire import NeedMore, STATIC, integer, string


class _Entry:
    """One dynamic table entry; entries are immutable once inserted."""

    __slots__ = ('name', 'value', 'size', 'seq')

    def __init__(self, name, value, seq):
        self.name = name
        self.value = value
        self.size = 32 + len(name) + len(value)
        self.seq = seq


class Decoder:
    def __init__(self, maximum, max_blocked):
        if type(maximum) is not int or isinstance(maximum, bool) or maximum < 32:
            raise ValueError('invalid maximum capacity')
        if type(max_blocked) is not int or isinstance(max_blocked, bool) or max_blocked < 1:
            raise ValueError('invalid max_blocked')
        self.maximum = maximum
        self.max_blocked = max_blocked
        # Dynamic table state
        self.table = deque()          # oldest -> newest, all within capacity
        self.capacity = 0             # current table capacity (starts at 0)
        self.insert_count = 0         # T: cumulative insert count
        self.table_size = 0
        # Stream / buffering state
        self.last = -1                # last accepted stream id
        self.blocked = []             # acceptance-ordered blocked block descriptors
        self.encoder_buf = bytearray()
        self.failed = False
        self.closed = False

    # ------------------------------------------------------------------ utils
    def _check(self):
        if self.failed:
            raise ValueError('decoder permanently failed')
        if self.closed:
            raise ValueError('decoder closed')

    def _fail(self, exc):
        self.failed = True
        if isinstance(exc, ValueError):
            return exc
        return ValueError(str(exc) or 'truncated input')

    def _has_entry(self, seq):
        """True iff absolute insert sequence seq is currently in the table."""
        if not self.table:
            return False
        first = self.table[0].seq
        newest = self.table[-1].seq
        return first <= seq <= newest

    @staticmethod
    def _take_raw(data, pos, length):
        """Read length raw bytes (name bytes carry no extra string wrapper)."""
        if len(data) - pos < length:
            raise NeedMore()
        return bytes(data[pos:pos + length]), pos + length

    def _entry(self, seq):
        # Called only after _has_entry / range validation.
        offset = seq - self.table[0].seq
        return self.table[offset]

    def _protected(self):
        """Absolute sequences that blocked header blocks may still read."""
        refs = set()
        for blk in self.blocked:
            refs.update(blk['refs'])
        return refs

    # ------------------------------------------------------------ header block
    def header(self, stream_id, block):
        self._check()
        try:
            if type(stream_id) is not int or isinstance(stream_id, bool) or stream_id <= self.last:
                raise ValueError('invalid stream id')
            if type(block) is not bytes or len(block) > 65536:
                raise ValueError('invalid header block')
            desc = self._parse_block(block)
            self.last = stream_id
            r = desc['r']
            if r > self.insert_count:
                if sum(1 for b in self.blocked if b['r'] > self.insert_count) >= self.max_blocked:
                    raise ValueError('too many blocked streams')
                self.blocked.append({'stream_id': stream_id, **desc})
                return []
            # Every reference is already present: render immediately, keep nothing.
            return [(stream_id, self._render(desc))]
        except (ValueError, NeedMore) as exc:
            raise self._fail(exc)

    def _decode_r(self, e):
        """Decode Encoded Insert Count against the frozen-at-acceptance T."""
        if e == 0:
            return 0
        m = self.maximum // 32
        f = 2 * m
        if e > f:
            raise ValueError('encoded insert count out of range')
        t = self.insert_count
        v = t + m
        w = (v // f) * f
        r = w + e - 1
        if r > v:
            if r <= f:
                raise ValueError('encoded insert count wraps before first full range')
            r -= f
        if r == 0:
            raise ValueError('encoded insert count resolves to zero')
        return r

    def _parse_block(self, block):
        """Parse a complete block; raises NeedMore/ValueError on bad input."""
        e, pos = integer(block, 0, 8)
        if pos >= len(block):
            raise ValueError('truncated header block: missing base delta byte')
        s = bool(block[pos] & 128)
        d, pos = integer(block, pos, 7)
        r = self._decode_r(e)
        base = r + d if not s else r - d - 1
        if base < 0:
            raise ValueError('negative base')

        fields = []
        refs = set()
        max_ref = 0
        accept_t = self.insert_count
        r0 = r == 0  # pre-base-compatible block: only static / literal fields

        def dyn(abs_seq):
            nonlocal max_ref
            if r0 or abs_seq <= 0 or abs_seq > r:
                raise ValueError('dynamic reference out of permitted range')
            if abs_seq <= accept_t and not self._has_entry(abs_seq):
                raise ValueError('reference to evicted dynamic entry')
            refs.add(abs_seq)
            if abs_seq > max_ref:
                max_ref = abs_seq

        while pos < len(block):
            byte = block[pos]
            if byte & 128:                       # 1Txxxxxx Indexed
                is_static = bool(byte & 64)
                i, pos = integer(block, pos, 6)
                if is_static:
                    if i not in STATIC:
                        raise ValueError('unsupported static index')
                    fields.append(('si', i))
                else:
                    if r0:
                        raise ValueError('dynamic index in an R=0 block')
                    dyn(base - i)
                    fields.append(('d', base - i))
            elif byte & 64:                      # 01NTxxxx Literal, name ref
                is_static = bool(byte & 8)      # N (never-index) accepted, ignored
                i, pos = integer(block, pos, 4)
                value, pos = string(block, pos)
                if is_static or r0:
                    # R=0 blocks retain the baseline static resolution so the
                    # frozen static regression stays valid (T bit is ignored).
                    if i not in STATIC:
                        raise ValueError('unsupported static index')
                    fields.append(('sn', i, value))
                else:
                    dyn(base - i)
                    fields.append(('dn', base - i, value))
            elif byte & 48 == 16:                # 0001xxxx Indexed Post-Base
                i, pos = integer(block, pos, 4)
                if r0:
                    raise ValueError('post-base index in an R=0 block')
                dyn(base + i + 1)
                fields.append(('d', base + i + 1))
            elif byte & 32:                      # 001NHxxx Literal literal name
                if byte & 8:
                    raise ValueError('Huffman literal name not supported')
                name_len, pos = integer(block, pos, 3)
                name, pos = self._take_raw(block, pos, name_len)
                value, pos = string(block, pos)
                fields.append(('lit', name, value))
            else:                                # 0000Nxxx Literal post-base name
                i, pos = integer(block, pos, 3)
                if r0:
                    raise ValueError('post-base name reference in an R=0 block')
                value, pos = string(block, pos)
                dyn(base + i + 1)
                fields.append(('dn', base + i + 1, value))

        if r == 0:
            if refs:
                raise ValueError('R=0 block contains dynamic references')
        elif max_ref != r:
            raise ValueError('largest dynamic reference does not equal R')
        return {'r': r, 'base': base, 'fields': fields, 'refs': refs}

    def _render(self, desc):
        out = []
        for f in desc['fields']:
            kind = f[0]
            if kind == 'si':
                out.append(STATIC[f[1]])
            elif kind == 'sn':
                out.append((STATIC[f[1]][0], f[2]))
            elif kind == 'lit':
                out.append((f[1], f[2]))
            elif kind == 'd':
                entry = self._entry(f[1])
                out.append((entry.name, entry.value))
            else:  # 'dn'
                entry = self._entry(f[1])
                out.append((entry.name, f[2]))
        return out

    # ------------------------------------------------------------ encoder feed
    def feed_encoder(self, chunk):
        self._check()
        try:
            if type(chunk) is not bytes or len(chunk) > 32768:
                raise ValueError('invalid encoder chunk')
            self.encoder_buf.extend(chunk)
            delivered = []
            while True:
                try:
                    inst, consumed = self._parse_instruction()
                except NeedMore:
                    break
                del self.encoder_buf[:consumed]
                self._execute(inst)
                # Unblock immediately after each complete instruction, before
                # any later instruction in the same chunk is processed.
                delivered.extend(self._unblock())
            return delivered
        except (ValueError, NeedMore) as exc:
            raise self._fail(exc)

    def _parse_instruction(self):
        """Return (instruction descriptor, consumed bytes); NeedMore if partial."""
        buf = self.encoder_buf
        if not buf:
            raise NeedMore()
        first = buf[0]
        if first & 128:                       # 1Txxxxxx Insert Name Reference
            tbit = bool(first & 64)
            i, pos = integer(buf, 0, 6)
            value, pos = string(buf, pos)
            return ('inr', tbit, i, value), pos
        if first & 64:                        # 01Hxxxxx Insert Literal
            if first & 32:
                raise ValueError('Huffman literal name not supported')
            name_len, pos = integer(buf, 0, 5)
            name, pos = self._take_raw(buf, pos, name_len)
            value, pos = string(buf, pos)
            return ('iln', name, value), pos
        if first & 32:                        # 001xxxxx Set Capacity
            cap, pos = integer(buf, 0, 5)
            return ('cap', cap), pos
        # 000xxxxx Duplicate
        rel, pos = integer(buf, 0, 5)
        return ('dup', rel), pos

    def _evict_for(self, needed_size):
        """FIFO eviction so a new entry of needed_size fits; capacity rules 9204 4.5."""
        if needed_size > self.capacity:
            raise ValueError('entry larger than current table capacity')
        protected = None
        while self.table_size + needed_size > self.capacity:
            oldest = self.table[0]
            if protected is None:
                protected = self._protected()
            if oldest.seq in protected:
                raise ValueError('cannot evict entry referenced by blocked header block')
            self.table.popleft()
            self.table_size -= oldest.size

    def _insert(self, name, value):
        entry = _Entry(name, value, self.insert_count + 1)
        self._evict_for(entry.size)
        self.table.append(entry)
        self.table_size += entry.size
        self.insert_count += 1

    def _execute(self, inst):
        kind = inst[0]
        if kind == 'cap':
            cap = inst[1]
            if cap > self.maximum:
                raise ValueError('capacity exceeds connection maximum')
            protected = None
            while self.table_size > cap:
                oldest = self.table[0]
                if protected is None:
                    protected = self._protected()
                if oldest.seq in protected:
                    raise ValueError('capacity reduction blocked by held reference')
                self.table.popleft()
                self.table_size -= oldest.size
            self.capacity = cap
            return
        if kind == 'dup':
            rel = inst[1]
            if rel >= len(self.table):          # prefix integer is always >= 0
                raise ValueError('duplicate relative index out of range')
            # Snapshot the source before any eviction (same name/value bytes).
            source = self.table[len(self.table) - 1 - rel]
            self._insert(bytes(source.name), bytes(source.value))
            return
        if kind == 'inr':
            _, tbit, i, value = inst
            if tbit:
                if i not in STATIC:
                    raise ValueError('unsupported static index')
                name = STATIC[i][0]
            else:
                if i >= len(self.table):
                    raise ValueError('dynamic name reference out of range')
                name = bytes(self.table[len(self.table) - 1 - i].name)
            self._insert(name, value)
            return
        # 'iln'
        _, name, value = inst
        self._insert(name, value)

    def _unblock(self):
        """Deliver every block whose R is now insertable, in acceptance order."""
        if not self.blocked:
            return []
        ready = []
        remaining = []
        for blk in self.blocked:
            if blk['r'] <= self.insert_count:
                ready.append((blk['stream_id'], self._render(blk)))
            else:
                remaining.append(blk)
        self.blocked = remaining
        return ready

    # ------------------------------------------------------------- lifecycle
    def cancel(self, stream_id):
        self._check()
        try:
            if type(stream_id) is not int or isinstance(stream_id, bool) or stream_id < 0:
                raise ValueError('invalid stream id')
            # Completed, unknown or already-cancelled ids: no effect.
            self.blocked = [b for b in self.blocked if b['stream_id'] != stream_id]
            return []
        except ValueError as exc:
            raise self._fail(exc)

    def finish(self):
        if self.failed:
            raise ValueError('decoder permanently failed')
        if self.closed:
            # finish() is the one call still allowed after a successful finish.
            return None
        if self.encoder_buf or self.blocked:
            self.failed = True
            raise ValueError('truncated encoder stream or unresolved blocked header block')
        self.closed = True
        return None

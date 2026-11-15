"""Frozen regressions for the existing static-only capture profile."""
import json
import sys
from qcapture import Decoder
from wire import NeedMore, integer, string


def normal():
    d = Decoder(128, 2)
    assert d.header(0, bytes.fromhex('0000d1d7c1')) == [(0, [(b':method', b'GET'), (b':scheme', b'https'), (b':path', b'/')])]
    assert d.header(4, bytes.fromhex('00005003616263')) == [(4, [(b':authority', b'abc')])]
    assert d.feed_encoder(b'') == []
    assert d.cancel(0) == []
    assert d.finish() is None
    assert integer(bytes.fromhex('1f9a0a'), 0, 5) == (1337, 3)
    assert string(b'\x03abc', 0) == (b'abc', 4)
    try:
        integer(b'\xff', 0, 8)
    except NeedMore:
        pass
    else:
        raise AssertionError('incremental integer')
    broken = Decoder(128, 2)
    for block in (b'\x00', b'\x00\x00\xd1'):
        try:
            broken.header(0, block)
        except ValueError:
            pass
        else:
            raise AssertionError('truncation and permanent failure')
    print('STATIC_CAPTURE_REGRESSION_OK')
    # New restricted dynamic profile: fully independent short-sequence and
    # randomized reference, byte-by-byte feeds, wrap-around, lifecycle and the
    # long-connection small-table memory observation.
    import refchecks
    refchecks.hand_cases()
    refchecks.randomized_cases()
    refchecks.long_connection()
    print('DYNAMIC_PROFILE_REFCHECK_OK')


def demo():
    """Show two header blocks blocked ahead of their dictionary entries, then
    restored in acceptance order as the encoder stream catches up."""
    from qcapture import Decoder

    def vint(value, prefix, lead):
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
        return vint(len(data), 7, 0) + data

    def insert(name, value):
        return vint(len(name), 5, 0x40) + name + vstr(value)

    steps = []
    from refchecks import Oracle
    d = Decoder(160, 4)
    o = Oracle(160, 4)
    steps.append(('set_capacity', d.feed_encoder(o.set_capacity(160))))

    # stream 3: R=3, Base=2 -> pre-base seq1 and post-base seq3
    block0, _ = o.submit(3, 3, 2, [('d', 1), ('d', 3)])
    steps.append(('header stream 3 (R=3, blocked at T=0)', d.header(3, block0)))
    # stream 5: R=4, Base=3 -> pre-base seq3, post-base seq4, static :status
    block1, _ = o.submit(5, 4, 3, [('d', 3), ('d', 4), ('si', 25)])
    steps.append(('header stream 5 (R=4, blocked at T=0)', d.header(5, block1)))

    # encoder dictionary arrives in deliberately ragged chunks
    dictionary = (insert(b'cache-key', b'alpha')      # seq1
                  + insert(b'cache-key', b'beta')    # seq2
                  + insert(b'etag', b'"v2"')         # seq3 -> stream 3 ready
                  + insert(b'etag', b'"v3"'))        # seq4 -> stream 5 ready
    cuts = [2, 1, 5, 3, 7, 4, 6]
    delivered, i = [], 0
    for cut in cuts:
        delivered += d.feed_encoder(dictionary[i:i + cut])
        i += cut
    delivered += d.feed_encoder(dictionary[i:])
    steps.append(('encoder dictionary fed in ragged chunks', delivered))
    steps.append(('finish', [] if d.finish() is None else ['unexpected']))

    def show(pair):
        label, rows = pair
        rendered = [[sid, [[n.decode('latin-1'), v.decode('latin-1')]
                           for n, v in fields]] for sid, fields in rows]
        return {'step': label, 'delivered': rendered}

    print(json.dumps([show(p) for p in steps], ensure_ascii=False, indent=2))


if __name__ == '__main__':
    {'normal': normal, 'demo': demo}[sys.argv[1]]()

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


def demo():
    rows = Decoder(128, 2).header(0, bytes.fromhex('0000d1d7c1'))
    print(json.dumps([[sid, [[n.decode(), v.decode()] for n, v in fields]] for sid, fields in rows]))


if __name__ == '__main__':
    {'normal': normal, 'demo': demo}[sys.argv[1]]()

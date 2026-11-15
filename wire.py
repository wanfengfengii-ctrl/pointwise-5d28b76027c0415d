"""Existing byte primitives, with no dynamic-table or blocked-stream implementation."""
class NeedMore(Exception):
    pass


def integer(data, position, prefix):
    if position >= len(data):
        raise NeedMore()
    value = data[position] & ((1 << prefix) - 1)
    position += 1
    if value != (1 << prefix) - 1:
        return value, position
    shift = 0
    while True:
        if position >= len(data):
            raise NeedMore()
        byte = data[position]
        position += 1
        value += (byte & 127) << shift
        if value > (1 << 31) - 1 or shift > 35:
            raise ValueError('integer overflow')
        if not byte & 128:
            return value, position
        shift += 7


def string(data, position):
    if position >= len(data):
        raise NeedMore()
    if data[position] & 128:
        raise ValueError('Huffman is outside this capture profile')
    length, position = integer(data, position, 7)
    if len(data) - position < length:
        raise NeedMore()
    return bytes(data[position:position+length]), position+length


STATIC = {0: (b':authority', b''), 1: (b':path', b'/'),
          17: (b':method', b'GET'), 23: (b':scheme', b'https'), 25: (b':status', b'200')}

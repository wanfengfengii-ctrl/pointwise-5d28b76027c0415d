"""Existing static-only QPACK capture profile; no target dynamic capability yet."""
from wire import NeedMore, STATIC, integer, string


class Decoder:
    def __init__(self, maximum, max_blocked):
        if type(maximum) is not int or maximum < 32 or type(max_blocked) is not int or max_blocked < 1:
            raise ValueError('invalid limits')
        self.maximum = maximum
        self.max_blocked = max_blocked
        self.last = -1
        self.failed = False

    def _check(self):
        if self.failed:
            raise ValueError('decoder permanently failed')

    def header(self, stream_id, block):
        self._check()
        try:
            if type(stream_id) is not int or stream_id <= self.last or type(block) is not bytes or len(block) > 65536:
                raise ValueError('invalid header submission')
            self.last = stream_id
            required, pos = integer(block, 0, 8)
            if pos >= len(block) or block[pos] & 128:
                raise ValueError('static profile base')
            base, pos = integer(block, pos, 7)
            if required or base:
                raise ValueError('dynamic headers not supported by existing baseline')
            fields = []
            while pos < len(block):
                byte = block[pos]
                if byte & 192 == 192:
                    index, pos = integer(block, pos, 6)
                    if index not in STATIC:
                        raise ValueError('unsupported static index')
                    fields.append(STATIC[index])
                elif byte & 208 == 80:
                    index, pos = integer(block, pos, 4)
                    if index not in STATIC:
                        raise ValueError('unsupported static index')
                    value, pos = string(block, pos)
                    fields.append((STATIC[index][0], value))
                else:
                    raise ValueError('unsupported static field')
            return [(stream_id, fields)]
        except (ValueError, NeedMore) as exc:
            self.failed = True
            raise ValueError(str(exc) or 'truncated header') from exc

    def feed_encoder(self, chunk):
        self._check()
        if type(chunk) is not bytes or chunk:
            self.failed = True
            raise ValueError('encoder stream is not supported by existing baseline')
        return []

    def cancel(self, stream_id):
        self._check()
        if type(stream_id) is not int or stream_id < 0:
            self.failed = True
            raise ValueError('stream id')
        return []

    def finish(self):
        self._check()
        return None

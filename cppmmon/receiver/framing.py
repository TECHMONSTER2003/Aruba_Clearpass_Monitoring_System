"""TCP syslog framing: RFC 6587 octet-counting and LF (non-transparent) framing."""
from __future__ import annotations


class SyslogFramer:
    """Incremental decoder for one TCP stream. ``feed`` returns complete (message, truncated) pairs.

    The framing mode is detected per message: a leading ``<digits><SP>`` is an
    octet count, anything else is LF-terminated. Messages longer than
    ``max_bytes`` are truncated and flagged; the remainder is discarded.
    """

    def __init__(self, max_bytes: int = 65536) -> None:
        self.max = max_bytes
        self.buf = bytearray()
        self._skip_lf = False  # discarding the tail of an oversized LF message
        self._skip_n = 0  # discarding the tail of an oversized octet-counted message

    def feed(self, data: bytes) -> list[tuple[bytes, bool]]:
        self.buf += data
        out: list[tuple[bytes, bool]] = []
        while True:
            if self._skip_n:
                n = min(self._skip_n, len(self.buf))
                del self.buf[:n]
                self._skip_n -= n
                if self._skip_n:
                    return out
            if self._skip_lf:
                i = self.buf.find(b"\n")
                if i < 0:
                    self.buf.clear()
                    return out
                del self.buf[: i + 1]
                self._skip_lf = False
            if not self.buf:
                return out
            if self.buf[:1].isdigit():
                sp = self.buf.find(b" ", 0, 12)
                if sp < 0:
                    if len(self.buf) > 12:  # not a count after all: treat as LF framed
                        pass
                    else:
                        return out  # wait for more bytes
                elif self.buf[:sp].isdigit():
                    n = int(self.buf[:sp])
                    start = sp + 1
                    if n > self.max:
                        if len(self.buf) - start < self.max:
                            return out
                        out.append((bytes(self.buf[start:start + self.max]), True))
                        consumed = start + self.max
                        remaining = n - self.max
                        take = min(remaining, len(self.buf) - consumed)
                        del self.buf[: consumed + take]
                        self._skip_n = remaining - take
                        continue
                    if len(self.buf) - start < n:
                        return out
                    out.append((bytes(self.buf[start:start + n]).rstrip(b"\r\n"), False))
                    del self.buf[: start + n]
                    continue
            i = self.buf.find(b"\n")
            if i < 0:
                if len(self.buf) > self.max:
                    out.append((bytes(self.buf[: self.max]), True))
                    self.buf.clear()
                    self._skip_lf = True
                return out
            line = bytes(self.buf[:i]).rstrip(b"\r")
            del self.buf[: i + 1]
            if line:
                if len(line) > self.max:
                    out.append((line[: self.max], True))
                else:
                    out.append((line, False))

    def flush(self) -> list[tuple[bytes, bool]]:
        """Connection closed: emit any unterminated final line."""
        if self.buf and not self._skip_lf and not self._skip_n:
            data = bytes(self.buf[: self.max]).rstrip(b"\r\n")
            trunc = len(self.buf) > self.max
            self.buf.clear()
            return [(data, trunc)] if data else []
        self.buf.clear()
        return []

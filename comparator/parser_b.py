"""Parser B: a minimal, independent reader for the SQLite file format.

It shares no code with Python's sqlite3 module (Parser A). It only supports
what the demo needs: UTF-8 databases, table b-trees (leaf and interior pages)
and records that fit on one page (no overflow pages). Anything else, or any
structural inconsistency, raises ParseError instead of guessing.

Format reference: https://www.sqlite.org/fileformat2.html
"""
import re
import struct

MAX_DEPTH = 32
MAX_COLUMNS = 2000
MAX_ROWS = 1_000_000
SQLITE_MAGIC = b"SQLite format 3\x00"
_INT_SIZES = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}
_CONSTRAINT_WORDS = {"PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "CONSTRAINT"}


class ParseError(Exception):
    """The input is not a database this parser can read safely."""


def _need(buf, pos, n):
    if pos < 0 or n < 0 or pos + n > len(buf):
        raise ParseError("read past end of buffer")


def _u16(buf, pos):
    _need(buf, pos, 2)
    return (buf[pos] << 8) | buf[pos + 1]


def _u32(buf, pos):
    _need(buf, pos, 4)
    return struct.unpack_from(">I", buf, pos)[0]


def _varint(buf, pos):
    """SQLite varint: up to 9 bytes, first 8 carry 7 bits, the 9th carries 8."""
    result = 0
    for i in range(8):
        _need(buf, pos + i, 1)
        b = buf[pos + i]
        result = (result << 7) | (b & 0x7F)
        if not b & 0x80:
            return result, pos + i + 1
    _need(buf, pos + 8, 1)
    result = (result << 8) | buf[pos + 8]
    return result, pos + 9


def _decode_value(buf, pos, serial_type):
    st = serial_type
    if st == 0:
        return None, pos
    if st in _INT_SIZES:
        n = _INT_SIZES[st]
        _need(buf, pos, n)
        return int.from_bytes(buf[pos:pos + n], "big", signed=True), pos + n
    if st == 7:
        _need(buf, pos, 8)
        return struct.unpack_from(">d", buf, pos)[0], pos + 8
    if st == 8:
        return 0, pos
    if st == 9:
        return 1, pos
    if st in (10, 11):
        raise ParseError("reserved serial type")
    if st % 2 == 0:
        n = (st - 12) // 2
        _need(buf, pos, n)
        return bytes(buf[pos:pos + n]), pos + n
    n = (st - 13) // 2
    _need(buf, pos, n)
    try:
        return bytes(buf[pos:pos + n]).decode("utf-8"), pos + n
    except UnicodeDecodeError:
        raise ParseError("text is not valid UTF-8")


def _parse_record(payload):
    header_size, pos = _varint(payload, 0)
    if header_size < 1 or header_size > len(payload):
        raise ParseError("bad record header size")
    types = []
    while pos < header_size:
        st, pos = _varint(payload, pos)
        types.append(st)
        if len(types) > MAX_COLUMNS:
            raise ParseError("too many columns")
    if pos != header_size:
        raise ParseError("record header overrun")
    body = header_size
    values = []
    for st in types:
        value, body = _decode_value(payload, body, st)
        values.append(value)
    return values


def _columns_from_sql(sql):
    """Return (column names, index of an INTEGER PRIMARY KEY alias or None)."""
    if not isinstance(sql, str):
        raise ParseError("missing CREATE TABLE statement")
    try:
        start = sql.index("(")
        end = sql.rindex(")")
    except ValueError:
        raise ParseError("cannot parse CREATE TABLE statement")
    if end <= start:
        raise ParseError("cannot parse CREATE TABLE statement")
    inner = sql[start + 1:end]
    parts, depth, cur = [], 0, ""
    for ch in inner:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    parts.append(cur.strip())
    cols, alias = [], None
    for part in parts:
        tokens = part.split()
        if not tokens:
            raise ParseError("empty column definition")
        if tokens[0].upper() in _CONSTRAINT_WORDS:
            continue
        if re.search(r"\bINTEGER\s+PRIMARY\s+KEY\b", part, re.IGNORECASE):
            alias = len(cols)
        cols.append(tokens[0].strip("\"`[]'"))
    return cols, alias


class MiniSQLite:
    def __init__(self, data):
        if len(data) < 100 or data[:16] != SQLITE_MAGIC:
            raise ParseError("not a SQLite database")
        page_size = _u16(data, 16)
        if page_size == 1:
            page_size = 65536
        if page_size < 512 or page_size & (page_size - 1):
            raise ParseError("invalid page size")
        encoding = _u32(data, 56)
        if encoding not in (0, 1):
            raise ParseError("only UTF-8 databases are supported")
        self.data = data
        self.page_size = page_size
        self.usable = page_size - data[20]
        self.n_pages = len(data) // page_size
        if self.n_pages < 1 or self.usable < 480:
            raise ParseError("invalid page layout")

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            return cls(f.read())

    def _page(self, number):
        if number < 1 or number > self.n_pages:
            raise ParseError("page number out of range")
        start = (number - 1) * self.page_size
        return self.data[start:start + self.page_size]

    def _walk(self, number, depth, seen):
        """Yield (rowid, payload) for every cell under a table b-tree page."""
        if depth > MAX_DEPTH:
            raise ParseError("b-tree too deep")
        if number in seen:
            raise ParseError("cycle detected in b-tree")
        seen.add(number)
        page = self._page(number)
        base = 100 if number == 1 else 0
        _need(page, base, 8)
        page_type = page[base]
        n_cells = _u16(page, base + 3)
        if page_type == 0x0D:
            max_local = self.usable - 35
            for i in range(n_cells):
                offset = _u16(page, base + 8 + 2 * i)
                size, p = _varint(page, offset)
                rowid, p = _varint(page, p)
                if size > max_local:
                    raise ParseError("overflow pages are not supported")
                _need(page, p, size)
                if rowid >= 1 << 63:
                    rowid -= 1 << 64
                yield rowid, page[p:p + size]
        elif page_type == 0x05:
            children = []
            for i in range(n_cells):
                offset = _u16(page, base + 12 + 2 * i)
                children.append(_u32(page, offset))
            children.append(_u32(page, base + 8))
            for child in children:
                yield from self._walk(child, depth + 1, seen)
        else:
            raise ParseError("unexpected b-tree page type")

    def tables(self):
        found = {}
        for _rowid, payload in self._walk(1, 0, set()):
            values = _parse_record(payload)
            if len(values) >= 5 and values[0] == "table" and isinstance(values[1], str):
                found[values[1]] = (values[3], values[4])
        return found

    def read_table(self, name):
        tables = self.tables()
        if name not in tables:
            raise ParseError("table not found")
        root, sql = tables[name]
        if not isinstance(root, int):
            raise ParseError("bad root page")
        cols, alias = _columns_from_sql(sql)
        rows = []
        for rowid, payload in self._walk(root, 0, set()):
            values = _parse_record(payload)
            if len(values) > len(cols):
                raise ParseError("record has more fields than the table schema")
            values += [None] * (len(cols) - len(values))
            if alias is not None:
                values[alias] = rowid
            rows.append(tuple(values))
            if len(rows) > MAX_ROWS:
                raise ParseError("too many rows")
        return cols, rows


def parse(db_path, table="messages"):
    return MiniSQLite.from_file(db_path).read_table(table)

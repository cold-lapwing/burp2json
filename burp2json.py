#!/usr/bin/env python3
"""
burp2json - convert Burp Suite research data into AI-friendly JSON.

Input formats (auto-detected, or force with --format):
  burp   Burp project file (.burp). The format is an undocumented object heap.
         This tool parses the heap directly (Proxy history, Repeater tabs,
         Target Site Map and Collaborator HTTP interactions). If the schema is
         not recognised it falls back to a byte-level HTTP carver, including
         zlib/gzip blobs.
  xml    Burp "Save items" XML export (Proxy / Repeater / Logger / Site map)
  har    HAR file (e.g. from burpparse file.burp -har)

Read-only: the input file is never modified.
Standard library only (optional: brotli for br-encoded bodies).

Use only on data from targets you are authorised to test.
"""
import argparse
import base64
import collections
import datetime
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import uuid
import zlib
from urllib.parse import urlsplit, parse_qsl
import xml.etree.ElementTree as ET

try:
    import brotli  # type: ignore
except Exception:  # pragma: no cover
    brotli = None

VERSION = "1.1.0"

METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS", b"TRACE", b"CONNECT")
REQ_RE = re.compile(rb"(?:%s) [^\r\n \x00]{1,8192} HTTP/(?:1\.[01]|2)\r?\n" % b"|".join(METHODS))
RESP_RE = re.compile(rb"HTTP/(?:1\.[01]|2) \d{3}[^\r\n]{0,200}\r?\n")
COLLAB_RE = re.compile(
    rb"[a-z0-9]{16,40}\.(?:oastify\.com|burpcollaborator\.net|oast\.(?:fun|pro|live|site|online|me))",
    re.I,
)

SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "x-auth-token", "x-csrf-token", "x-xsrf-token", "api-key", "x-access-token",
}
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
SECRET_KV_RE = re.compile(
    r'(?i)("?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"?\s*[:=]\s*"?)([^"&\s,}]{3,})'
)

AI_INSTRUCTIONS = (
    "This JSON was produced from a Burp Suite project by burp2json. 'summary' gives the "
    "application overview (hosts, endpoints, parameters, cookies, status codes, tech). "
    "'items' holds each HTTP request/response pair with ALL headers preserved "
    "(headers are [name, value] lists to keep order and duplicates). Bodies are UTF-8 text "
    "unless body_encoding is 'base64'. 'source_tool' is 'proxy', 'repeater', 'site-map' or "
    "'unknown'; 'also_seen_in' lists other Burp tools that stored the same exchange. "
    "'collaborator' contains payload domains and HTTP interactions recovered from the project. "
    "Review for: access control, IDOR, auth/session handling, injection points, CORS, "
    "security headers, information disclosure, and business-logic flaws. "
    "Values marked [REDACTED] were removed by the user before sharing."
)

HIGHLIGHT_COLORS = {
    0: "none", 1: "red", 2: "orange", 3: "yellow", 4: "green",
    5: "cyan", 6: "blue", 7: "pink", 8: "magenta", 9: "gray",
}
BURP_MIME = {
    0x0100: "HTML", 0x0101: "TEXT", 0x0102: "CSS", 0x0103: "SCRIPT",
    0x0104: "JSON", 0x0106: "XML",
}


# ----------------------------------------------------------------------------
# HTTP message parsing
# ----------------------------------------------------------------------------
def _decode_chunked(data):
    out, pos = b"", 0
    while True:
        eol = data.find(b"\n", pos)
        if eol == -1:
            return out, False
        size_str = data[pos:eol].strip().split(b";")[0]
        try:
            size = int(size_str, 16)
        except ValueError:
            return out, False
        pos = eol + 1
        if size == 0:
            return out, True
        out += data[pos:pos + size]
        pos += size
        if data[pos:pos + 2] == b"\r\n":
            pos += 2
        elif data[pos:pos + 1] == b"\n":
            pos += 1


def _decompress(body, encoding):
    enc = (encoding or "").lower().strip()
    if not enc:
        return body, None
    try:
        if "gzip" in enc:
            return gzip.decompress(body), None
        if "deflate" in enc:
            try:
                return zlib.decompress(body), None
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), None
        if "br" in enc:
            if brotli is None:
                return body, "brotli body left compressed (pip install brotli)"
            return brotli.decompress(body), None
        if "zstd" in enc:
            return body, "zstd body left compressed (not supported by the standard library)"
    except Exception as e:
        return body, "decompress failed: %s" % e
    return body, None


def _header_value(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def encode_body(body, max_body):
    if not body:
        return {"body": "", "body_encoding": "utf-8", "body_length": 0, "body_truncated": False}
    truncated = len(body) > max_body
    shown = body[:max_body]
    try:
        text = shown.decode("utf-8")
        enc = "utf-8"
        controls = sum(1 for b in shown if b < 9 or (13 < b < 32))
        if shown and controls >= max(1, len(shown) * 0.05):
            text, enc = base64.b64encode(shown).decode(), "base64"
    except UnicodeDecodeError:
        if sum(1 for b in shown if b < 9 or (13 < b < 32)) < len(shown) * 0.05:
            text, enc = shown.decode("latin-1"), "latin-1"
        else:
            text, enc = base64.b64encode(shown).decode(), "base64"
    return {"body": text, "body_encoding": enc, "body_length": len(body), "body_truncated": truncated}


def parse_http(raw, is_request, max_body=200_000, strict_end=None):
    """Parse raw HTTP/1.x or HTTP/2 textual bytes.

    Returns (dict, consumed_bytes, warnings) or None. ``strict_end`` tells the
    parser how many bytes belong to this message so a body without a
    Content-Length header is not silently discarded.
    """
    warnings = []
    sep = raw.find(b"\r\n\r\n")
    sep_len = 4
    if sep == -1:
        sep = raw.find(b"\n\n")
        sep_len = 2
    if sep == -1:
        return None
    head = raw[:sep].decode("latin-1")
    lines = head.replace("\r\n", "\n").split("\n")
    first = lines[0].strip()
    headers = []
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers.append([k.strip(), v.strip()])
    body_start = sep + sep_len
    rest = raw[body_start:]
    cl = _header_value(headers, "content-length")
    te = (_header_value(headers, "transfer-encoding") or "").lower()
    consumed_extra = 0
    if "chunked" in te:
        body, complete = _decode_chunked(rest)
        if not complete:
            warnings.append("chunked body incomplete")
        consumed_extra = len(rest) if strict_end is None else min(len(rest), max(strict_end - body_start, 0))
    elif cl and cl.isdigit():
        n = int(cl)
        body = rest[:n]
        if len(body) < n:
            warnings.append("body shorter than Content-Length (%d < %d)" % (len(body), n))
        consumed_extra = len(body)
    elif strict_end is not None:
        body = rest[:max(strict_end - body_start, 0)]
        consumed_extra = len(body)
    else:
        body = b""
        consumed_extra = 0
    msg = {"headers": headers}
    if is_request:
        parts = first.split(" ")
        if len(parts) < 3:
            return None
        msg["method"], msg["target"], msg["http_version"] = parts[0], parts[1], parts[-1]
        msg["request_line"] = first
    else:
        m = re.match(r"HTTP/(\S+)\s+(\d{3})\s*(.*)", first)
        if not m:
            return None
        msg["http_version"], msg["status"], msg["reason"] = m.group(1), int(m.group(2)), m.group(3)
        msg["status_line"] = first
    decoded, w = _decompress(body, _header_value(headers, "content-encoding"))
    if w:
        warnings.append(w)
    msg.update(encode_body(decoded, max_body))
    ct = _header_value(headers, "content-type")
    if ct:
        msg["content_type"] = ct.split(";")[0].strip().lower()
    return msg, body_start + consumed_extra, warnings


def enrich_request(req, host_hint=None):
    cookies, params = {}, []
    for k, v in req.get("headers", []):
        if k.lower() == "cookie":
            for part in v.split(";"):
                if "=" in part:
                    ck, cv = part.strip().split("=", 1)
                    cookies[ck] = cv
    target = req.get("target", "")
    split = urlsplit(target)
    req["path"] = split.path or "/"
    req["query_params"] = [[k, v] for k, v in parse_qsl(split.query, keep_blank_values=True)]
    ct = req.get("content_type", "")
    if req.get("body") and req.get("body_encoding") != "base64":
        if ct == "application/x-www-form-urlencoded":
            params = [[k, v] for k, v in parse_qsl(req["body"], keep_blank_values=True)]
        elif ct.endswith("json"):
            try:
                obj = json.loads(req["body"])
                if isinstance(obj, dict):
                    params = [[k, v if isinstance(v, (str, int, float, bool)) or v is None
                               else "<%s>" % type(v).__name__] for k, v in obj.items()]
            except Exception:
                pass
    req["cookies"] = cookies
    req["body_params"] = params
    host = _header_value(req["headers"], "host") or host_hint
    req["host_header"] = host
    return req


# ----------------------------------------------------------------------------
# Burp project heap parser
# ----------------------------------------------------------------------------
class BurpFormatError(ValueError):
    pass


class BurpProject:
    """Read-only parser for the outer object heap used by current .burp files.

    The format is a 72-byte big-endian header followed by a heap of compact,
    self-describing objects and length-framed byte/array records. Persisted
    references are signed big-endian 64-bit addresses.
    """

    HEADER_SIZE = 72
    MAGIC = 0x66858280
    MAX_OUTER_VERSION = 1
    MAX_COMPATIBILITY = -2142078604

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.view = memoryview(self.data)
        self.header = self._parse_header()

    # -- low level ---------------------------------------------------------
    def _need(self, offset, size):
        if offset < 0 or offset + size > len(self.data):
            raise BurpFormatError("read at %d+%d exceeds project data" % (offset, size))

    def u8(self, offset):
        self._need(offset, 1)
        return self.data[offset]

    def i16(self, offset):
        self._need(offset, 2)
        return struct.unpack_from(">h", self.data, offset)[0]

    def u16(self, offset):
        self._need(offset, 2)
        return struct.unpack_from(">H", self.data, offset)[0]

    def i32(self, offset):
        self._need(offset, 4)
        return struct.unpack_from(">i", self.data, offset)[0]

    def i64(self, offset):
        self._need(offset, 8)
        return struct.unpack_from(">q", self.data, offset)[0]

    def _parse_header(self):
        if len(self.data) < self.HEADER_SIZE:
            raise BurpFormatError("project is smaller than the 72-byte header")
        magic, outer_version, compatibility = struct.unpack_from(">Iii", self.data, 0)
        if magic != self.MAGIC:
            raise BurpFormatError("invalid project magic 0x%08x" % magic)
        if outer_version < 0 or outer_version > self.MAX_OUTER_VERSION:
            raise BurpFormatError("unsupported outer version %d" % outer_version)
        if compatibility > self.MAX_COMPATIBILITY:
            raise BurpFormatError("unsupported compatibility value %d" % compatibility)
        schema_floor, schema_current = struct.unpack_from(">HH", self.data, 12)
        random_id = struct.unpack_from(">I", self.data, 16)[0]
        metadata_root, span, cursor, project_root = struct.unpack_from(">qqqq", self.data, 40)
        if span <= 0 or cursor < self.HEADER_SIZE or metadata_root < 0 or project_root < 0:
            raise BurpFormatError("invalid header roots or allocation cursor")
        if cursor > len(self.data):
            raise BurpFormatError("allocation cursor %d exceeds file size %d" % (cursor, len(self.data)))
        return {
            "magic": "0x%08x" % magic,
            "outer_version": outer_version,
            "compatibility": "0x%08x" % (compatibility & 0xFFFFFFFF),
            "schema_floor": schema_floor,
            "schema_current": schema_current,
            "random_identifier": random_id,
            "metadata_root": metadata_root,
            "segment_span": span,
            "allocation_cursor": cursor,
            "project_root": project_root,
            "file_size": len(self.data),
        }

    # -- compact objects ---------------------------------------------------
    def parse_object(self, address, max_depth=16):
        visited = set()
        current = address
        for _ in range(max_depth + 1):
            if current in visited:
                raise BurpFormatError("forwarding cycle at %d" % current)
            visited.add(current)
            self._need(current, 4)
            flags = self.data[current]
            if flags & 1:
                fwd = self.i64(current + 1)
                if fwd <= 0:
                    raise BurpFormatError("invalid forwarding address %d" % fwd)
                current = fwd
                continue
            type_id = self.data[current + 1]
            subtype = self.data[current + 2]
            count = self.data[current + 3]
            table_end = current + 4 + count * 3
            self._need(current, 4 + count * 3)
            fields = {}
            previous = 4 + count * 3 - 1
            for index in range(count):
                entry = current + 4 + index * 3
                field_id = self.data[entry]
                rel = struct.unpack_from(">h", self.data, entry + 1)[0]
                if field_id >= 128:
                    raise BurpFormatError("invalid field id %d" % field_id)
                if field_id in fields:
                    raise BurpFormatError("duplicate field id %d" % field_id)
                if rel < 4 + count * 3 or rel <= previous:
                    raise BurpFormatError("bad field offset for id %d" % field_id)
                previous = rel
                fields[field_id] = rel
            for rel in fields.values():
                if current + rel >= len(self.data):
                    raise BurpFormatError("field address outside project")
            return {"address": current, "type": type_id, "subtype": subtype,
                    "flags": flags, "fields": fields}
        raise BurpFormatError("forwarding depth exceeded at %d" % address)

    def field_offset(self, obj, field_id):
        rel = obj["fields"].get(field_id)
        if rel is None:
            return None
        return obj["address"] + rel

    def read_address(self, obj, field_id):
        off = self.field_offset(obj, field_id)
        if off is None:
            return None
        value = self.i64(off)
        if value < 0:
            raise BurpFormatError("negative address in field %d" % field_id)
        return None if value == 0 else value

    def read_i32(self, obj, field_id):
        off = self.field_offset(obj, field_id)
        return None if off is None else self.i32(off)

    def read_i64(self, obj, field_id):
        off = self.field_offset(obj, field_id)
        return None if off is None else self.i64(off)

    def read_i16(self, obj, field_id):
        off = self.field_offset(obj, field_id)
        return None if off is None else self.i16(off)

    def read_u8(self, obj, field_id):
        off = self.field_offset(obj, field_id)
        return None if off is None else self.u8(off)

    def read_bytes_field(self, obj, field_id, width):
        off = self.field_offset(obj, field_id)
        if off is None:
            return None
        self._need(off, width)
        return self.data[off:off + width]

    # -- framed records ----------------------------------------------------
    def variable_record(self, address):
        if not address:
            raise BurpFormatError("null record address")
        self._need(address, 8)
        total, logical = struct.unpack_from(">ii", self.data, address)
        if logical < 0:
            raise BurpFormatError("negative record length at %d" % address)
        expected = 8 + max(logical, 1)
        if total != expected:
            raise BurpFormatError("record at %d has total %d, expected %d" % (address, total, expected))
        self._need(address + 8, logical)
        return self.data[address + 8:address + 8 + logical]

    def variable_array(self, address, element_size):
        if not address:
            raise BurpFormatError("null array address")
        if element_size <= 0:
            raise BurpFormatError("invalid element size")
        self._need(address, 8)
        total, count = struct.unpack_from(">ii", self.data, address)
        if count < 0:
            raise BurpFormatError("negative array count at %d" % address)
        payload_size = count * element_size
        expected = 8 + max(payload_size, 1)
        if total != expected:
            raise BurpFormatError("array at %d has total %d, expected %d" % (address, total, expected))
        self._need(address + 8, payload_size)
        return count, self.data[address + 8:address + 8 + payload_size]

    def address_array(self, address):
        count, payload = self.variable_array(address, 8)
        values = list(struct.unpack(">%dq" % count, payload)) if count else []
        out = []
        for value in values:
            if value < 0:
                raise BurpFormatError("negative address in address array")
            out.append(None if value == 0 else value)
        return out

    def text_frame(self, address):
        count, payload = self.variable_array(address, 2)
        try:
            return payload.decode("utf-16-be", "replace")
        except Exception:
            return payload.decode("latin-1", "replace")

    def immutable_string(self, address):
        if not address:
            return None
        obj = self.parse_object(address)
        chars = self.read_address(obj, 0)
        if chars is None:
            return None
        return self.text_frame(chars)

    def text_wrapper(self, address):
        if not address:
            return None
        obj = self.parse_object(address)
        for field_id in (0, 1, 2):
            chars = self.read_address(obj, field_id)
            if chars is not None:
                try:
                    text = self.text_frame(chars)
                    if text and all(ch == "\t" or ch == "\n" or ch == "\r" or ch >= " " for ch in text):
                        return text
                except BurpFormatError:
                    continue
        return None

    def mutable_string(self, address):
        if not address:
            return None
        try:
            obj = self.parse_object(address)
            length = self.read_i32(obj, 0)
            chunks_addr = self.read_address(obj, 3)
            if length is None or chunks_addr is None:
                return self.immutable_string(address)
            chunks = self.direct_collection(chunks_addr)
            text = "".join(self.text_frame(chunk) for chunk in chunks if chunk)
            return text[:length]
        except BurpFormatError:
            return self.immutable_string(address)

    def direct_collection(self, address):
        obj = self.parse_object(address)
        size = self.read_i32(obj, 0)
        backing = self.read_address(obj, 1)
        if size is None or backing is None:
            raise BurpFormatError("direct collection missing size or backing array")
        addresses = self.address_array(backing)
        if size > len(addresses):
            raise BurpFormatError("direct collection size exceeds backing array")
        return addresses[:size]

    def chunked_collection(self, address):
        obj = self.parse_object(address)
        size = self.read_i32(obj, 0)
        chunk_size = self.read_i32(obj, 1)
        chunk_list_addr = self.read_address(obj, 2)
        leading = self.read_i32(obj, 3)
        if None in (size, chunk_size, chunk_list_addr, leading):
            raise BurpFormatError("chunked collection is missing a required field")
        if size < 0 or chunk_size <= 0 or leading < 0:
            raise BurpFormatError("invalid chunked collection dimensions")
        chunk_list = self.parse_object(chunk_list_addr)
        chunk_count = self.read_i32(chunk_list, 0)
        array_addr = self.read_address(chunk_list, 1)
        if chunk_count is None or array_addr is None:
            raise BurpFormatError("chunk list is missing a required field")
        chunk_addresses = self.address_array(array_addr)
        if chunk_count > len(chunk_addresses):
            raise BurpFormatError("chunk count exceeds address array")
        cache = {}
        out = []
        for logical in range(size):
            physical = leading + logical
            chunk_index, slot = divmod(physical, chunk_size)
            if chunk_index >= chunk_count:
                raise BurpFormatError("missing chunk %d" % chunk_index)
            chunk_addr = chunk_addresses[chunk_index]
            if not chunk_addr:
                raise BurpFormatError("null chunk address")
            if chunk_addr not in cache:
                cache[chunk_addr] = self.address_array(chunk_addr)
            slots = cache[chunk_addr]
            if slot >= len(slots):
                raise BurpFormatError("slot outside chunk")
            out.append(slots[slot])
        return out

    def uuid_object(self, address):
        if not address:
            return None
        obj = self.parse_object(address)
        high = self.read_i64(obj, 0)
        low = self.read_i64(obj, 1)
        if high is None or low is None:
            return None
        return str(uuid.UUID(int=((high & 0xFFFFFFFFFFFFFFFF) << 64) | (low & 0xFFFFFFFFFFFFFFFF)))

    # -- semantic helpers --------------------------------------------------
    def service(self, row):
        metadata_addr = self.read_address(row, 2)
        if not metadata_addr:
            return None
        metadata = self.parse_object(metadata_addr)
        service_addr = self.read_address(metadata, 0)
        if not service_addr:
            return None
        service = self.parse_object(service_addr)
        host_wrapper_addr = self.read_address(service, 0)
        host = None
        if host_wrapper_addr:
            wrapper = self.parse_object(host_wrapper_addr)
            text_addr = self.read_address(wrapper, 0)
            if text_addr:
                host = self.text_frame(text_addr)
        return {
            "host": host,
            # Schema 217 stores the port as a 32-bit integer followed by the
            # one-byte TLS flag. Reading eight bytes here folds the flag into
            # the port (e.g. 443 + TLS becomes 0x1bb01000000).
            "port": self.read_i32(service, 1),
            "tls": bool(self.read_u8(service, 2)) if self.read_u8(service, 2) is not None else None,
            "request_metadata_address": metadata_addr,
            "service_address": service_addr,
        }

    def comment(self, row):
        # Schema 217 stores the note in field 3; newer schemas use field 27.
        for field_id in (3, 27):
            addr = self.read_address(row, field_id)
            if not addr:
                continue
            text = self.text_wrapper(addr)
            if text is not None:
                return text
            try:
                wrapper = self.parse_object(addr)
            except BurpFormatError:
                continue
            current = self.read_address(wrapper, 2) or self.read_address(wrapper, 1)
            seen = set()
            parts = []
            while current and current not in seen and len(seen) < 10_000:
                seen.add(current)
                try:
                    chunk = self.parse_object(current)
                    text_addr = self.read_address(chunk, 1)
                    length = self.read_i32(chunk, 2)
                    if text_addr:
                        value = self.text_frame(text_addr)
                        parts.append(value[:length] if length is not None else value)
                    current = self.read_address(chunk, 3)
                except BurpFormatError:
                    break
            if parts:
                return "".join(parts)
        return None

    def row(self, address):
        obj = self.parse_object(address)
        meta = {
            "entry_id": self.read_i32(obj, 0),
            "method_hint": self.immutable_string(self.read_address(obj, 1)),
            "ip": self.immutable_string(self.read_address(obj, 4)),
            "status": self.read_i16(obj, 6),
            "burp_mime_code": self.read_i16(obj, 7),
            "burp_mime": None,
            "response_length": self.read_i32(obj, 8),
            "title": self.immutable_string(self.read_address(obj, 9)),
            "cookie_header": self.immutable_string(self.read_address(obj, 10)),
            "time_epoch_ms": self.read_i64(obj, 11),
            "highlight": HIGHLIGHT_COLORS.get(self.read_u8(obj, 13) or 0, "unknown"),
            "listener_port": self.read_i32(obj, 14),
            "comment": self.comment(obj),
            "service": self.service(obj),
            "timing_1": self.read_i64(obj, 28),
            "timing_2": self.read_i64(obj, 29),
            "secondary_time_epoch_ms": self.read_i64(obj, 30),
            "row_address": address,
        }
        meta["burp_mime"] = BURP_MIME.get(meta["burp_mime_code"])
        return meta

    def _first_address(self, obj, field_ids):
        for field_id in field_ids:
            addr = self.read_address(obj, field_id)
            if addr:
                return addr
        return None

    # -- extraction --------------------------------------------------------
    def extract_proxy(self, warnings):
        root = self.parse_object(self.header["project_root"])
        proxy_addr = self.read_address(root, 1)
        if not proxy_addr:
            return []
        proxy = self.parse_object(proxy_addr)
        seen = set()
        out = []
        for collection_field in (0, 1):
            collection_addr = self.read_address(proxy, collection_field)
            if not collection_addr:
                continue
            try:
                items = self.chunked_collection(collection_addr)
            except BurpFormatError as e:
                warnings.append("Proxy collection %d could not be decoded: %s" % (collection_field, e))
                continue
            for item_addr in items:
                if not item_addr or item_addr in seen:
                    continue
                seen.add(item_addr)
                try:
                    row = self.parse_object(item_addr)
                    req_addr = self._first_address(row, (15, 16, 17))
                    resp_addr = self._first_address(row, (18, 19, 20))
                    req_raw = self.variable_record(req_addr) if req_addr else None
                    resp_raw = self.variable_record(resp_addr) if resp_addr else None
                    if not req_raw and not resp_raw:
                        continue
                    meta = self.row(item_addr)
                    meta["proxy_collections"] = [collection_field]
                except BurpFormatError as e:
                    warnings.append("Proxy row %d could not be decoded: %s" % (item_addr, e))
                    continue
                if req_raw and not re.match(rb"^(?:%s) " % b"|".join(METHODS), req_raw):
                    warnings.append("Proxy row %d request bytes do not start with an HTTP method" % item_addr)
                    continue
                if resp_raw and not resp_raw.startswith(b"HTTP/"):
                    warnings.append("Proxy row %d response bytes do not start with HTTP/" % item_addr)
                    resp_raw = None
                out.append({
                    "source": "proxy", "request_addr": req_addr, "response_addr": resp_addr,
                    "request_raw": req_raw, "response_raw": resp_raw, "meta": meta,
                })
        return out

    def extract_repeater(self, warnings):
        root = self.parse_object(self.header["project_root"])
        repeater_addr = self.read_address(root, 2)
        if not repeater_addr:
            return [], {"tabs": [], "groups": []}
        repeater = self.parse_object(repeater_addr)
        tab_coll = self.read_address(repeater, 1)
        group_coll = self.read_address(repeater, 4)
        groups = []
        if group_coll:
            try:
                for group_addr in self.direct_collection(group_coll):
                    if not group_addr:
                        continue
                    group = self.parse_object(group_addr)
                    groups.append({
                        "address": group_addr,
                        "name": self.immutable_string(self.read_address(group, 0)),
                        "color": self.read_u8(group, 1),
                        "expanded": bool(self.read_u8(group, 2)) if self.read_u8(group, 2) is not None else None,
                        "index": self.read_i32(group, 3),
                        "uuid": self.uuid_object(self.read_address(group, 4)),
                    })
            except BurpFormatError as e:
                warnings.append("Repeater groups could not be decoded: %s" % e)
        group_by_addr = {g["address"]: g for g in groups}
        tabs_out = []
        out = []
        if tab_coll:
            try:
                tab_addresses = self.direct_collection(tab_coll)
            except BurpFormatError as e:
                warnings.append("Repeater tab collection could not be decoded: %s" % e)
                tab_addresses = []
            for tab_addr in tab_addresses:
                if not tab_addr:
                    continue
                try:
                    tab = self.parse_object(tab_addr)
                    caption_addr = self.read_address(tab, 0)
                    caption = self.mutable_string(caption_addr) if caption_addr else None
                    group_addr = self.read_address(tab, 32)
                    tab_info = {
                        "address": tab_addr,
                        "caption": caption,
                        "uuid": self.uuid_object(self.read_address(tab, 33)),
                        "group": group_by_addr.get(group_addr),
                        "pair_count": 0,
                    }
                    pair_coll = self.read_address(tab, 2)
                    pair_addresses = []
                    if pair_coll:
                        try:
                            pair_addresses = self.direct_collection(pair_coll)
                        except BurpFormatError:
                            try:
                                pair_addresses = self.chunked_collection(pair_coll)
                            except BurpFormatError as e:
                                warnings.append("Repeater pairs for tab %s could not be decoded: %s" % (caption, e))
                    pair_index = 0
                    for pair_addr in pair_addresses:
                        if not pair_addr:
                            continue
                        pair = self.parse_object(pair_addr)
                        req_addr = self.read_address(pair, 2)
                        resp_addr = self.read_address(pair, 3)
                        req_raw = self.variable_record(req_addr) if req_addr else None
                        resp_raw = self.variable_record(resp_addr) if resp_addr else None
                        if not req_raw and not resp_raw:
                            continue
                        pair_index += 1
                        out.append({
                            "source": "repeater", "request_addr": req_addr,
                            "response_addr": resp_addr, "request_raw": req_raw,
                            "response_raw": resp_raw,
                            "meta": {
                                "tab": caption, "tab_uuid": tab_info["uuid"],
                                "group": tab_info["group"], "pair_index": pair_index,
                            },
                        })
                    tab_info["pair_count"] = pair_index
                    tabs_out.append(tab_info)
                except BurpFormatError as e:
                    warnings.append("Repeater tab %d could not be decoded: %s" % (tab_addr, e))
        return out, {"tabs": tabs_out, "groups": groups}

    def extract_site_map(self, warnings):
        root = self.parse_object(self.header["project_root"])
        target_addr = self.read_address(root, 3)
        if not target_addr:
            return []
        target = self.parse_object(target_addr)
        index_addr = self.read_address(target, 3)
        if not index_addr:
            return []
        index = self.parse_object(index_addr)
        expected_size = self.read_i32(index, 2)
        bucket_coll = self.read_address(index, 3)
        if expected_size is None or not bucket_coll:
            return []
        try:
            buckets = self.chunked_collection(bucket_coll)
        except BurpFormatError as e:
            warnings.append("Target identity index could not be decoded: %s" % e)
            return []
        out = []
        seen_messages = set()
        decoded_entries = 0
        for bucket_addr in buckets:
            if not bucket_addr:
                continue
            try:
                bucket = self.parse_object(bucket_addr)
                bucket_size = self.read_i32(bucket, 0)
                tuple_addr = self.read_address(bucket, 1)
                if bucket_size is None or not tuple_addr:
                    continue
                count, payload = self.variable_array(tuple_addr, 24)
                if bucket_size > count:
                    continue
                for index_entry in range(bucket_size):
                    _hash, key_addr, _value = struct.unpack_from(">qqq", payload, index_entry * 24)
                    if key_addr <= 0:
                        continue
                    decoded_entries += 1
                    node = self.parse_object(key_addr)
                    message_addr = self.read_address(node, 33)
                    if not message_addr or message_addr in seen_messages:
                        continue
                    seen_messages.add(message_addr)
                    message = self.parse_object(message_addr)
                    req_addr = self.read_address(message, 0)
                    resp_addr = self.read_address(message, 1)
                    req_raw = self.variable_record(req_addr) if req_addr else None
                    resp_raw = self.variable_record(resp_addr) if resp_addr else None
                    if not req_raw and not resp_raw:
                        continue
                    if req_raw and not re.match(rb"^(?:%s) " % b"|".join(METHODS), req_raw):
                        continue
                    if resp_raw and not resp_raw.startswith(b"HTTP/"):
                        resp_raw = None
                    out.append({
                        "source": "site-map", "request_addr": req_addr,
                        "response_addr": resp_addr, "request_raw": req_raw,
                        "response_raw": resp_raw,
                        "meta": {
                            "node_type": node["type"], "node_subtype": node["subtype"],
                            "node_address": key_addr, "message_address": message_addr,
                            # Field 3 is the capture time in epoch milliseconds.
                            "time_epoch_ms": self.read_i64(message, 3),
                        },
                    })
            except BurpFormatError as e:
                warnings.append("Target bucket %d could not be decoded: %s" % (bucket_addr, e))
        if expected_size and decoded_entries != expected_size:
            warnings.append("Target index reported %d entries; decoded %d" % (expected_size, decoded_entries))
        return out

    def scan_frames(self):
        """Find length-framed HTTP records without trusting the object graph."""
        marks = [(m.start(), "request") for m in REQ_RE.finditer(self.data)]
        marks += [(m.start(), "response") for m in RESP_RE.finditer(self.data)]
        frames = []
        seen = set()
        for offset, kind in sorted(marks):
            record = offset - 8
            if record < self.HEADER_SIZE or record in seen:
                continue
            try:
                total, logical = struct.unpack_from(">ii", self.data, record)
            except struct.error:
                continue
            if logical <= 0 or total != 8 + logical or offset + logical > len(self.data):
                continue
            payload = self.data[offset:offset + logical]
            if kind == "request" and not re.match(rb"^(?:%s) " % b"|".join(METHODS), payload):
                continue
            if kind == "response" and not payload.startswith(b"HTTP/"):
                continue
            seen.add(record)
            frames.append({"address": record, "kind": kind, "payload": payload})
        return frames

    def collaborator(self, frames, warnings):
        domains = {m.group(0).decode("ascii", "replace").lower()
                   for m in COLLAB_RE.finditer(self.data)}
        requests = []
        responses = []
        for frame in frames:
            payload = frame["payload"]
            if frame["kind"] == "request" and COLLAB_RE.search(payload):
                requests.append(frame)
            elif frame["kind"] == "response" and b"Burp Collaborator" in payload[:4096]:
                responses.append(frame)
        for frame in requests + responses:
            for match in COLLAB_RE.finditer(frame["payload"]):
                domains.add(match.group(0).decode("ascii", "replace").lower())
        interactions = []
        used_responses = set()
        for request in requests:
            candidates = [r for r in responses if r["address"] not in used_responses]
            if not candidates:
                response = None
            else:
                response = min(candidates, key=lambda r: abs(r["address"] - request["address"]))
                used_responses.add(response["address"])
            req_msg = None
            resp_msg = None
            req_parsed = parse_http(request["payload"], True, 50_000, strict_end=len(request["payload"]))
            if req_parsed:
                req_msg = req_parsed[0]
            if response:
                resp_parsed = parse_http(response["payload"], False, 50_000,
                                         strict_end=len(response["payload"]))
                if resp_parsed:
                    resp_msg = resp_parsed[0]
            if not req_msg:
                continue
            enrich_request(req_msg)
            host = req_msg.get("host_header") or ""
            interactions.append({
                "type": "HTTP",
                "host": host,
                "method": req_msg.get("method"),
                "path": req_msg.get("path"),
                "request_line": req_msg.get("request_line"),
                "response_status": resp_msg.get("status") if resp_msg else None,
                "response_server": _header_value(resp_msg["headers"], "server") if resp_msg else None,
                "request_address": request["address"],
                "response_address": response["address"] if response else None,
                "request": req_msg,
                "response": resp_msg,
            })
        if requests and not responses:
            warnings.append("Collaborator requests were found but no HTTP interaction responses were recovered")
        return {
            "domains_seen": sorted(domains),
            "interaction_types_seen": ["HTTP"] if interactions else [],
            "interactions": interactions,
            "note": ("HTTP interactions are recovered from framed request/response records. "
                     "DNS/SMTP interaction logs are not stored as ordinary HTTP frames and are "
                     "not recovered by this parser."),
        }

    def extract(self, max_body, warnings):
        proxy = self.extract_proxy(warnings)
        repeater, repeater_info = self.extract_repeater(warnings)
        site_map = self.extract_site_map(warnings)
        all_exchanges = proxy + repeater + site_map

        frames = self.scan_frames()
        by_address = {f["address"]: f for f in frames}
        known_addresses = set()
        for exchange in all_exchanges:
            for key in ("request_addr", "response_addr"):
                if exchange.get(key):
                    known_addresses.add(exchange[key])

        collaborator = self.collaborator(frames, warnings)
        collaborator_addresses = set()
        for interaction in collaborator["interactions"]:
            collaborator_addresses.add(interaction["request_address"])
            if interaction["response_address"]:
                collaborator_addresses.add(interaction["response_address"])

        unattributed = [f for f in frames
                        if f["address"] not in known_addresses
                        and f["address"] not in collaborator_addresses]
        if unattributed:
            warnings.append(
                "%d framed HTTP record(s) were not linked to Proxy, Repeater, Site Map or "
                "Collaborator metadata (first addresses: %s)"
                % (len(unattributed), ", ".join(str(f["address"]) for f in unattributed[:8]))
            )

        # Make sure every frame referenced by metadata is a real HTTP frame.
        for exchange in all_exchanges:
            for side, addr_key in (("request", "request_addr"), ("response", "response_addr")):
                addr = exchange.get(addr_key)
                if addr and addr not in by_address:
                    warnings.append("%s frame at %d was referenced but did not validate" % (side, addr))

        root = self.parse_object(self.header["project_root"])
        project_name = None
        try:
            project_name = self.immutable_string(self.read_address(root, 6))
        except BurpFormatError:
            pass

        coverage = {
            "proxy_items": len(proxy),
            "repeater_pairs": len(repeater),
            "site_map_messages": len(site_map),
            "framed_http_records": len(frames),
            "unattributed_frames": len(unattributed),
            "collaborator_http_interactions": len(collaborator["interactions"]),
        }
        return {
            "items": all_exchanges,
            "collaborator": collaborator,
            "repeater": repeater_info,
            "coverage": coverage,
            "project_name": project_name,
            "header": self.header,
        }


# ----------------------------------------------------------------------------
# Fallback carver
# ----------------------------------------------------------------------------
def carve_buffer(buf, base_offset, max_body, depth=0):
    marks = [(m.start(), "request") for m in REQ_RE.finditer(buf)]
    marks += [(m.start(), "response") for m in RESP_RE.finditer(buf)]
    marks.sort()
    found = []
    for i, (off, kind) in enumerate(marks):
        limit = marks[i + 1][0] - off if i + 1 < len(marks) else min(len(buf) - off, 8_000_000)
        chunk = buf[off:off + limit]
        parsed = parse_http(chunk, kind == "request", max_body, strict_end=None)
        if not parsed:
            continue
        msg, _used, warns = parsed
        found.append({"offset": base_offset + off, "kind": kind, "msg": msg,
                      "warnings": warns, "depth": depth})
    return found


def find_compressed_streams(buf, limit=64_000_000):
    n = len(buf)
    i = 0
    while i < n - 2:
        b0 = buf[i]
        out = None
        if b0 == 0x78 and buf[i + 1] in (0x01, 0x5E, 0x9C, 0xDA) and ((b0 << 8) | buf[i + 1]) % 31 == 0:
            try:
                d = zlib.decompressobj()
                out = d.decompress(buf[i:i + 8_000_000], limit)
            except zlib.error:
                out = None
        elif b0 == 0x1F and buf[i + 1] == 0x8B and buf[i + 2] == 8:
            try:
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                out = d.decompress(buf[i:i + 8_000_000], limit)
            except zlib.error:
                out = None
        if out and len(out) >= 16 and b"HTTP/" in out:
            yield i, out
        i += 1


def pair_carved(found, source="unknown"):
    found.sort(key=lambda x: x["offset"])
    items, current = [], None
    for frame in found:
        if frame["kind"] == "request":
            current = {"request": frame["msg"], "request_addr": frame["offset"],
                       "response": None, "response_addr": None,
                       "warnings": list(frame["warnings"]), "source": source,
                       "meta": {}}
            items.append(current)
        else:
            if current is not None and current["response"] is None:
                current["response"] = frame["msg"]
                current["response_addr"] = frame["offset"]
                current["warnings"] += frame["warnings"]
            else:
                items.append({"request": None, "request_addr": None,
                              "response": frame["msg"], "response_addr": frame["offset"],
                              "warnings": list(frame["warnings"]), "source": source,
                              "meta": {}})
    return items


def read_burp_fallback(path, max_body, warnings):
    with open(path, "rb") as f:
        data = f.read()
    found = carve_buffer(data, 0, max_body)
    compressed = 0
    extra_collab = set()
    for off, out in find_compressed_streams(data):
        extra_collab.update(m.group(0).decode("ascii", "replace").lower()
                            for m in COLLAB_RE.finditer(out))
        sub = carve_buffer(out, off, max_body, depth=1)
        if sub:
            compressed += 1
            found.extend(sub)
    if compressed:
        warnings.append("recovered messages from %d compressed blob(s)" % compressed)
    items = pair_carved(found)
    collab = sorted({m.group(0).decode("ascii", "replace").lower()
                     for m in COLLAB_RE.finditer(data)} | extra_collab)
    if collab:
        warnings.append("collaborator-style domains seen in file (%d)" % len(collab))
    warnings.append("fallback carver cannot recover tool names, tab names, comments, highlights, "
                    "Intruder configuration or Collaborator interaction logs")
    return items, "frame-carver", {
        "collaborator": {"domains_seen": collab, "interaction_types_seen": [],
                         "interactions": [],
                         "note": "only payload domains are recoverable in fallback mode"},
        "repeater": {"tabs": [], "groups": []},
        "coverage": {"proxy_items": 0, "repeater_pairs": 0, "site_map_messages": 0,
                     "framed_http_records": len(found), "unattributed_frames": len(found),
                     "collaborator_http_interactions": 0},
        "project_name": None, "header": None,
    }


def read_burp(path, max_body, warnings):
    # 1) Structural heap parser (preferred).
    try:
        project = BurpProject(path)
        result = project.extract(max_body, warnings)
        if result["items"]:
            return result["items"], "burp-heap", result
        warnings.append("structural parser found no HTTP items; falling back to frame carver")
    except Exception as e:
        warnings.append("structural parser failed (%s); falling back to frame carver" % e)

    # 2) Optional external burpparse -> HAR.
    exe = shutil.which("burpparse")
    if exe:
        try:
            res = subprocess.run([exe, path, "-har"], capture_output=True, timeout=600)
            if res.returncode == 0 and res.stdout.strip().startswith(b"{"):
                items = read_har_bytes(res.stdout, max_body)
                if items:
                    return items, "burpparse(-har)", {
                        "collaborator": {"domains_seen": [], "interaction_types_seen": [],
                                         "interactions": [], "note": "HAR has no Collaborator data"},
                        "repeater": {"tabs": [], "groups": []},
                        "coverage": {}, "project_name": None, "header": None,
                    }
            warnings.append("burpparse present but produced no usable HAR")
        except Exception as e:
            warnings.append("burpparse failed: %s" % e)

    # 3) Byte-level carver.
    return read_burp_fallback(path, max_body, warnings)


# ----------------------------------------------------------------------------
# XML and HAR readers
# ----------------------------------------------------------------------------
def _raw_from_b64_or_text(el):
    if el is None or el.text is None:
        return b""
    if el.get("base64") == "true":
        return base64.b64decode(el.text)
    return el.text.encode("utf-8", "surrogateescape")


def read_xml(path, max_body, warnings):
    tree = ET.parse(path)
    items = []
    for it in tree.getroot().iter("item"):
        req_raw = _raw_from_b64_or_text(it.find("request"))
        resp_raw = _raw_from_b64_or_text(it.find("response"))
        host_el = it.find("host")
        source_tool = (it.findtext("type") or it.get("type") or "xml-export").strip()
        entry = {
            "request": None, "response": None, "warnings": [],
            "source_tool": source_tool,
            "time": (it.findtext("time") or None),
            "url": it.findtext("url"),
            "host": (host_el.text if host_el is not None else None),
            "ip": (host_el.get("ip") if host_el is not None else None),
            "port": it.findtext("port"),
            "protocol": it.findtext("protocol"),
            "comment": it.findtext("comment"),
            "meta": {},
        }
        if req_raw:
            p = parse_http(req_raw, True, max_body, strict_end=len(req_raw))
            if p:
                entry["request"] = p[0]
                entry["warnings"] += p[2]
        if resp_raw:
            p = parse_http(resp_raw, False, max_body, strict_end=len(resp_raw))
            if p:
                entry["response"] = p[0]
                entry["warnings"] += p[2]
        if not entry["request"] and not entry["response"]:
            warnings.append("XML item has no parseable request or response")
            continue
        items.append(entry)
    return items, "burp-xml"


def read_har_bytes(raw, max_body):
    har = json.loads(raw)
    items = []
    for e in har.get("log", {}).get("entries", []):
        rq, rs = e.get("request", {}), e.get("response", {})
        req = {
            "method": rq.get("method"), "target": rq.get("url"),
            "http_version": rq.get("httpVersion"),
            "request_line": "%s %s %s" % (rq.get("method"), rq.get("url"), rq.get("httpVersion")),
            "headers": [[h.get("name", ""), h.get("value", "")] for h in rq.get("headers", [])],
        }
        pd = rq.get("postData") or {}
        req.update(encode_body((pd.get("text") or "").encode("utf-8", "replace"), max_body))
        if pd.get("mimeType"):
            req["content_type"] = pd["mimeType"].split(";")[0].lower()
        cont = rs.get("content") or {}
        text = cont.get("text") or ""
        body = base64.b64decode(text) if cont.get("encoding") == "base64" else text.encode("utf-8", "replace")
        resp = {
            "status": rs.get("status"), "reason": rs.get("statusText"),
            "http_version": rs.get("httpVersion"),
            "status_line": "%s %s %s" % (rs.get("httpVersion"), rs.get("status"), rs.get("statusText")),
            "headers": [[h.get("name", ""), h.get("value", "")] for h in rs.get("headers", [])],
        }
        resp.update(encode_body(body, max_body))
        if cont.get("mimeType"):
            resp["content_type"] = cont["mimeType"].split(";")[0].lower()
        items.append({
            "request": req, "response": resp, "warnings": [],
            "source_tool": "har", "time": e.get("startedDateTime"),
            "url": rq.get("url"), "comment": e.get("comment"), "meta": {},
        })
    return items


def read_har(path, max_body, warnings):
    with open(path, "rb") as f:
        return read_har_bytes(f.read(), max_body), "har"


# ----------------------------------------------------------------------------
# Post-processing
# ----------------------------------------------------------------------------
def _split_host_port(host_header):
    if not host_header:
        return None, None
    if host_header.startswith("["):
        end = host_header.find("]")
        if end != -1:
            host = host_header[1:end]
            rest = host_header[end + 1:]
            port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
            return host, port
    if ":" in host_header:
        host, port_text = host_header.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)
    return host_header, None


def _infer_url(req, meta, default_scheme=None, default_port=None):
    target = req.get("target", "") if req else ""
    if target.startswith("http://") or target.startswith("https://"):
        split = urlsplit(target)
        scheme = split.scheme or "http"
        host = split.hostname
        port = split.port or (443 if scheme == "https" else 80)
        return target, host, port, scheme
    service = (meta or {}).get("service") or {}
    host_header = _header_value(req.get("headers", []), "host") if req else None
    host, port = service.get("host"), service.get("port")
    if not host:
        host, port = _split_host_port(host_header)
    tls = service.get("tls")
    if default_scheme in ("http", "https"):
        scheme = default_scheme
    elif tls is None:
        if port:
            tls = port in (443, 8443)
        elif (req or {}).get("http_version") in ("2", "HTTP/2"):
            tls = True
        else:
            tls = False
        scheme = "https" if tls else "http"
    else:
        scheme = "https" if tls else "http"
    if default_port:
        try:
            port = int(default_port)
        except (TypeError, ValueError):
            pass
    if not host:
        return None, None, None, None
    if not port:
        port = 443 if scheme == "https" else 80
    display_host = host
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        display_host = "%s:%d" % (host, port)
    if target.startswith("/"):
        return "%s://%s%s" % (scheme, display_host, target), host, port, scheme
    if target:
        return "%s://%s/%s" % (scheme, display_host, target), host, port, scheme
    return "%s://%s/" % (scheme, display_host), host, port, scheme


def _time_iso(epoch_ms):
    if not epoch_ms:
        return None
    try:
        return datetime.datetime.fromtimestamp(epoch_ms / 1000.0, datetime.timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def _exchange_key(item):
    req = item.get("request_raw") or b""
    resp = item.get("response_raw") or b""
    h = hashlib.sha256()
    h.update(len(req).to_bytes(8, "big"))
    h.update(req)
    h.update(len(resp).to_bytes(8, "big"))
    h.update(resp)
    return h.hexdigest()


def merge_exchanges(exchanges):
    priority = {"proxy": 0, "repeater": 1, "site-map": 2, "unknown": 3}
    merged = {}
    order = []
    for exchange in exchanges:
        key = _exchange_key(exchange)
        if key not in merged:
            exchange = dict(exchange)
            exchange["also_seen_in"] = []
            merged[key] = exchange
            order.append(key)
            continue
        current = merged[key]
        if current["source"] != exchange["source"]:
            current.setdefault("also_seen_in", []).append(exchange["source"])
        if priority.get(exchange["source"], 9) < priority.get(current["source"], 9):
            old_source = current["source"]
            old_also = current.get("also_seen_in", [])
            exchange = dict(exchange)
            exchange["also_seen_in"] = sorted(set(old_also + [old_source]))
            merged[key] = exchange
    for exchange in merged.values():
        exchange["also_seen_in"] = sorted(set(exchange.get("also_seen_in", [])))
    return [merged[key] for key in order]


def _normalize_source(value):
    text = str(value or "unknown").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "target": "site-map",
        "sitemap": "site-map",
        "proxy-history": "proxy",
        "http-history": "proxy",
        "xml-export": "unknown",
    }
    return aliases.get(text, text or "unknown")


def finalize_items(items, max_body=200_000):
    """Parse raw exchanges (heap or carver) and build the public item schema."""
    out = []
    for raw_item in items:
        source = _normalize_source(raw_item.get("source", raw_item.get("source_tool", "unknown")))
        req_raw = raw_item.get("request_raw")
        resp_raw = raw_item.get("response_raw")
        req = raw_item.get("request")
        resp = raw_item.get("response")
        warnings = list(raw_item.get("warnings", []))
        meta = dict(raw_item.get("meta") or {})
        if req_raw is not None and req is None:
            parsed = parse_http(req_raw, True, max_body, strict_end=len(req_raw))
            if parsed:
                req, _used, warns = parsed
                warnings += warns
        if resp_raw is not None and resp is None:
            parsed = parse_http(resp_raw, False, max_body, strict_end=len(resp_raw))
            if parsed:
                resp, _used, warns = parsed
                warnings += warns
        if not req and not resp:
            continue
        if req:
            enrich_request(req)
        url, host, port, scheme = _infer_url(
            req, meta,
            default_scheme=raw_item.get("protocol"),
            default_port=raw_item.get("port"),
        )
        if not host:
            host = raw_item.get("host")
        if not port and raw_item.get("port"):
            try:
                port = int(raw_item["port"])
            except (TypeError, ValueError):
                port = None
        if not scheme:
            scheme = raw_item.get("protocol")
        status = resp.get("status") if resp else meta.get("status")
        comment = raw_item.get("comment") or meta.get("comment")
        time_value = raw_item.get("time") or meta.get("time_epoch_ms")
        if isinstance(time_value, str) and time_value.isdigit():
            time_value = int(time_value)
        item = {
            "id": len(out) + 1,
            "source_tool": source,
            "also_seen_in": sorted(set(raw_item.get("also_seen_in", []))),
            "time": time_value,
            "time_iso": _time_iso(time_value) if isinstance(time_value, int) else None,
            "url": url or raw_item.get("url"),
            "host": host,
            "port": port,
            "protocol": scheme,
            "method": req.get("method") if req else raw_item.get("method"),
            "path": req.get("path") if req else None,
            "status": status,
            "comment": comment,
            "highlight": meta.get("highlight") or raw_item.get("highlight"),
            "metadata": meta,
            "request": req,
            "response": resp,
        }
        if raw_item.get("request_addr") is not None:
            item["request_file_offset"] = raw_item["request_addr"]
        if raw_item.get("response_addr") is not None:
            item["response_file_offset"] = raw_item["response_addr"]
        if warnings:
            item["warnings"] = warnings
        out.append(item)
    return out


def redact_value(s):
    s = JWT_RE.sub("[REDACTED_JWT]", s)
    return SECRET_KV_RE.sub(lambda m: m.group(1) + "[REDACTED]", s)


def redact_message(msg):
    if not msg:
        return
    for h in msg.get("headers", []):
        if h[0].lower() in SENSITIVE_HEADERS:
            h[1] = "[REDACTED]"
        else:
            h[1] = redact_value(h[1])
    if msg.get("cookies"):
        msg["cookies"] = {k: "[REDACTED]" for k in msg["cookies"]}
    if msg.get("body_encoding") != "base64" and msg.get("body"):
        msg["body"] = redact_value(msg["body"])
    for lst in ("query_params", "body_params"):
        for kv in msg.get(lst, []):
            if len(kv) > 1 and re.search(r"(?i)pass|secret|token|key|auth|session|jwt", str(kv[0])):
                kv[1] = "[REDACTED]"
    for key in ("target", "request_line"):
        if msg.get(key):
            msg[key] = redact_value(msg[key])


def redact_items(items):
    for item in items:
        redact_message(item.get("request"))
        redact_message(item.get("response"))
        if item.get("url"):
            item["url"] = redact_value(item["url"])
        if item.get("comment"):
            item["comment"] = redact_value(item["comment"])
        meta = item.get("metadata")
        if isinstance(meta, dict):
            # Burp records the Cookie request header separately from the raw
            # request (used to populate its history table).
            if meta.get("cookie_header"):
                meta["cookie_header"] = "[REDACTED]"
            if meta.get("title"):
                meta["title"] = redact_value(meta["title"])
    return items


def redact_collaborator(collab):
    for interaction in collab.get("interactions", []):
        redact_message(interaction.get("request"))
        redact_message(interaction.get("response"))
    return collab


def build_summary(items):
    hosts = collections.Counter()
    host_details = collections.defaultdict(lambda: {"ports": set(), "protocols": set()})
    endpoints = collections.defaultdict(lambda: {"count": 0, "statuses": collections.Counter(), "params": set()})
    status = collections.Counter()
    methods = collections.Counter()
    ctypes = collections.Counter()
    tech = collections.Counter()
    cookies, auth = set(), set()
    param_names = set()
    sec_missing = collections.Counter()
    redirects, errors, client_errors = [], [], []
    source_tools = collections.Counter()
    highlights = collections.Counter()
    for item in items:
        source_tools[item.get("source_tool", "unknown")] += 1
        if item.get("highlight"):
            highlights[item["highlight"]] += 1
        host = item.get("host")
        if host:
            hosts[host] += 1
            if item.get("port"):
                host_details[host]["ports"].add(item["port"])
            if item.get("protocol"):
                host_details[host]["protocols"].add(item["protocol"])
        req, resp = item.get("request"), item.get("response")
        if req:
            methods[req.get("method")] += 1
            ep = endpoints[(host, req.get("method"), req.get("path"))]
            ep["count"] += 1
            for k, _ in req.get("query_params", []) + req.get("body_params", []):
                ep["params"].add(k)
                param_names.add(k)
            cookies.update(req.get("cookies", {}).keys())
            for k, _ in req.get("headers", []):
                if k.lower() in ("authorization", "x-api-key", "x-auth-token", "x-csrf-token", "proxy-authorization"):
                    auth.add(k)
            if resp:
                ep["statuses"][resp.get("status")] += 1
        if resp:
            status[str(resp.get("status"))] += 1
            if resp.get("content_type"):
                ctypes[resp["content_type"]] += 1
            for h in ("server", "x-powered-by", "x-aspnet-version", "via"):
                value = _header_value(resp.get("headers", []), h)
                if value:
                    tech["%s: %s" % (h, value)] += 1
            names = {k.lower() for k, _ in resp.get("headers", [])}
            if (resp.get("status") or 0) < 300:
                for h in ("strict-transport-security", "content-security-policy",
                          "x-content-type-options", "x-frame-options"):
                    if h not in names:
                        sec_missing[h] += 1
            location = _header_value(resp.get("headers", []), "location")
            if 300 <= (resp.get("status") or 0) < 400:
                redirects.append({"id": item["id"], "url": item.get("url"),
                                  "status": resp.get("status"), "location": location})
            if (resp.get("status") or 0) >= 500:
                errors.append({"id": item["id"], "url": item.get("url"), "status": resp.get("status")})
            elif 400 <= (resp.get("status") or 0) < 500:
                client_errors.append({"id": item["id"], "url": item.get("url"),
                                      "status": resp.get("status")})
    ep_list = [{"host": h, "method": m, "path": p, "count": v["count"],
                "statuses": dict(v["statuses"]), "params": sorted(v["params"])}
               for (h, m, p), v in sorted(endpoints.items(),
                                          key=lambda kv: (str(kv[0][0]), str(kv[0][2])))]
    return {
        "total_items": len(items),
        "source_tool_counts": dict(source_tools),
        "hosts": dict(hosts.most_common()),
        "host_details": [
            {"host": h, "count": hosts[h], "ports": sorted(v["ports"]),
             "protocols": sorted(v["protocols"])}
            for h, v in sorted(host_details.items())
        ],
        "endpoints": ep_list,
        "parameter_names": sorted(param_names),
        "methods": dict(methods),
        "status_codes": dict(status),
        "content_types": dict(ctypes.most_common()),
        "technology_headers": dict(tech),
        "cookie_names_seen": sorted(cookies),
        "auth_header_names_seen": sorted(auth),
        "responses_missing_security_headers": dict(sec_missing),
        "redirects": redirects,
        "client_errors": client_errors[:100],
        "server_errors": errors[:50],
        "highlights": dict(highlights),
    }


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def detect_format(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".burp":
        return "burp"
    if ext == ".har":
        return "har"
    if ext == ".xml":
        return "xml"
    with open(path, "rb") as f:
        head = f.read(512).lstrip()
    if head.startswith(b"<?xml") or head.startswith(b"<items"):
        return "xml"
    if head.startswith(b"{"):
        return "har"
    if len(head) >= 4 and head[:4] == b"\x66\x85\x82\x80":
        return "burp"
    return "burp"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Convert Burp Suite data (.burp / XML export / HAR) to AI-friendly JSON.")
    ap.add_argument("input")
    ap.add_argument("-o", "--output", help="output .json (default: <input>.json)")
    ap.add_argument("--format", choices=["burp", "xml", "har"], help="force input format")
    ap.add_argument("--max-body", type=int, default=200_000,
                    help="max bytes of each body to keep (default 200000)")
    ap.add_argument("--host", action="append",
                    help="keep only items whose host contains this (repeatable)")
    ap.add_argument("--redact", action="store_true",
                    help="redact auth headers, cookies, JWTs, secret-looking fields")
    ap.add_argument("--chunk-items", type=int, default=0,
                    help="split into files of N items each (for AI context limits)")
    ap.add_argument("--no-summary", action="store_true")
    args = ap.parse_args(argv)

    if args.max_body < 0:
        ap.error("--max-body must be >= 0")
    if args.chunk_items < 0:
        ap.error("--chunk-items must be >= 0")
    if not os.path.isfile(args.input):
        ap.error("input file not found: %s" % args.input)

    fmt = args.format or detect_format(args.input)
    warnings = []
    extra = {}
    if fmt == "burp":
        raw_items, method, extra = read_burp(args.input, args.max_body, warnings)
    elif fmt == "xml":
        raw_items, method = read_xml(args.input, args.max_body, warnings)
    else:
        raw_items, method = read_har(args.input, args.max_body, warnings)

    if fmt == "burp" and method == "burp-heap":
        raw_items = merge_exchanges(raw_items)
    items = finalize_items(raw_items, args.max_body)
    if args.host:
        items = [i for i in items
                 if i.get("host") and any(h.lower() in i["host"].lower() for h in args.host)]
        for n, item in enumerate(items, 1):
            item["id"] = n
    if args.redact:
        redact_items(items)
        if extra.get("collaborator"):
            redact_collaborator(extra["collaborator"])
    if not items:
        warnings.append("NO HTTP items recovered. Try opening the project in Burp and using "
                        "Proxy > HTTP history > select all > right-click > Save items (XML), "
                        "then run this tool on the XML export.")

    with open(args.input, "rb") as f:
        data = f.read()
    sha = hashlib.sha256(data).hexdigest()

    header = extra.get("header") or {}
    burp_info = {
        "magic": header.get("magic"),
        "outer_version": header.get("outer_version"),
        "compatibility": header.get("compatibility"),
        "schema_floor": header.get("schema_floor"),
        "schema_current": header.get("schema_current"),
        "project_name": extra.get("project_name"),
        "burp_version": None,
        "burp_version_note": ("Burp project files store a format schema, not the exact Burp "
                              "release. schema_current is reported instead."),
    }
    if not header:
        burp_info = None

    meta = {
        "tool": "burp2json",
        "tool_version": VERSION,
        "source_file": os.path.basename(args.input),
        "source_sha256": sha,
        "source_size": len(data),
        "input_format": fmt,
        "extraction_method": method,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "read_only": True,
        "item_count": len(items),
        "source_tool_counts": dict(collections.Counter(i.get("source_tool", "unknown") for i in items)),
        "redacted": bool(args.redact),
        "burp": burp_info,
        "warnings": warnings,
    }

    doc = {"ai_instructions": AI_INSTRUCTIONS, "meta": meta}
    if not args.no_summary:
        doc["summary"] = build_summary(items)
    doc["collaborator"] = extra.get("collaborator") or {
        "domains_seen": [], "interaction_types_seen": [], "interactions": [],
        "note": "Collaborator data is only recovered from .burp input.",
    }
    doc["repeater"] = extra.get("repeater") or {"tabs": [], "groups": []}
    doc["intruder"] = {
        "recovered": False,
        "note": ("Intruder attack configuration, payload positions, payload lists and results are "
                 "not stored in the Proxy heap path used here. Export them from Burp if needed."),
    }
    doc["scanner"] = {
        "recovered": False,
        "note": ("Scanner/audit items are not enumerated by this parser. The project root's "
                 "Scanner Dashboard state exists, but task/item ownership is not mapped."),
    }
    doc["coverage"] = extra.get("coverage") or {}

    out = args.output or (args.input + ".json")
    written = []
    if args.chunk_items and len(items) > args.chunk_items:
        n = args.chunk_items
        parts = [items[i:i + n] for i in range(0, len(items), n)]
        base, ext = os.path.splitext(out)
        for idx, part in enumerate(parts, 1):
            part_doc = {
                "ai_instructions": AI_INSTRUCTIONS,
                "meta": dict(meta, part=idx, parts=len(parts)),
            }
            if idx == 1 and not args.no_summary:
                part_doc["summary"] = doc.get("summary")
            part_doc["collaborator"] = doc["collaborator"] if idx == 1 else {
                "domains_seen": [], "interaction_types_seen": [], "interactions": [],
                "note": "see part 1",
            }
            part_doc["repeater"] = doc["repeater"] if idx == 1 else {"tabs": [], "groups": []}
            part_doc["intruder"] = doc["intruder"] if idx == 1 else {"recovered": False, "note": "see part 1"}
            part_doc["scanner"] = doc["scanner"] if idx == 1 else {"recovered": False, "note": "see part 1"}
            part_doc["coverage"] = doc["coverage"] if idx == 1 else {}
            part_doc["items"] = part
            path = "%s_part%03d%s" % (base, idx, ext or ".json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(part_doc, f, indent=2, ensure_ascii=False)
            written.append(path)
    else:
        doc["items"] = items
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        written.append(out)

    print("method=%s items=%d" % (method, len(items)), file=sys.stderr)
    for warning in warnings:
        print("warning: " + warning, file=sys.stderr)
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

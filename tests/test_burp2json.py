"""Tests for burp2json.

Run with:  python3 -m unittest discover -s tests -v
"""

import base64
import gzip
import json
import os
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import burp2json as b2j  # noqa: E402


# ---------------------------------------------------------------------------
# Minimal schema-217 project writer
# ---------------------------------------------------------------------------
class HeapWriter:
    """Builds the subset of the Burp object heap needed by the tests."""

    BASE = 72
    MAGIC = 0x66858280
    COMPATIBILITY = -2142078604  # 0x80527974

    def __init__(self):
        self.body = bytearray()

    def _add(self, data):
        address = self.BASE + len(self.body)
        self.body.extend(data)
        return address

    def record(self, payload):
        logical = len(payload)
        total = 8 + max(logical, 1)
        return self._add(struct.pack(">ii", total, logical) + payload
                         + (b"\x00" if not payload else b""))

    def array(self, payload, element_size):
        count = len(payload) // element_size
        total = 8 + max(len(payload), 1)
        return self._add(struct.pack(">ii", total, count) + payload
                         + (b"\x00" if not payload else b""))

    def text(self, value):
        return self.array(value.encode("utf-16-be"), 2)

    def immutable_string(self, value):
        return self.obj([(0, "addr", self.text(value))])

    def obj(self, fields, type_id=0, subtype=0):
        """fields: iterable of (field_id, kind, value)."""
        sizes = {"addr": 8, "i64": 8, "i32": 4, "i16": 2, "u8": 1}
        fields = sorted(fields, key=lambda item: item[0])
        count = len(fields)
        header_size = 4 + count * 3
        table = bytearray([0, type_id, subtype, count])
        values = bytearray()
        rel = header_size
        for field_id, kind, value in fields:
            table.extend(bytes([field_id]) + struct.pack(">h", rel))
            if kind == "addr":
                values.extend(struct.pack(">q", value))
            elif kind == "i64":
                values.extend(struct.pack(">q", value))
            elif kind == "i32":
                values.extend(struct.pack(">i", value))
            elif kind == "i16":
                values.extend(struct.pack(">h", value))
            elif kind == "u8":
                values.extend(struct.pack(">B", value))
            else:  # pragma: no cover - programming error in tests
                raise ValueError("unknown field kind %r" % kind)
            rel += sizes[kind]
        return self._add(bytes(table + values))

    def chunked_collection(self, items):
        # One chunk holding every slot; the chunk list stores chunk
        # addresses, and each chunk is itself an address array of slots.
        chunk = self.array(b"".join(struct.pack(">q", item) for item in items), 8)
        chunk_list_backing = self.array(struct.pack(">q", chunk), 8)
        chunk_list = self.obj([(0, "i32", 1), (1, "addr", chunk_list_backing)])
        return self.obj([
            (0, "i32", len(items)),
            (1, "i32", max(1, len(items))),
            (2, "addr", chunk_list),
            (3, "i32", 0),
        ])

    def direct_collection(self, items):
        backing = self.array(b"".join(struct.pack(">q", item) for item in items), 8)
        return self.obj([(0, "i32", len(items)), (1, "addr", backing)])

    def finish(self, project_root):
        span = 0x7FFFFFFFFFFFFFFF
        cursor = self.BASE + len(self.body)
        header = bytearray(72)
        struct.pack_into(">Iii", header, 0, self.MAGIC, 1, self.COMPATIBILITY)
        struct.pack_into(">HH", header, 12, 217, 217)
        struct.pack_into(">I", header, 16, 0x12345678)
        struct.pack_into(">qqqq", header, 40, 0, span, cursor, project_root)
        return bytes(header + self.body)


def build_project(path):
    """Write a small .burp project and return the expected metadata."""
    heap = HeapWriter()

    req = heap.record(
        b"GET /api/items?x=1 HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Cookie: sid=super-secret\r\n"
        b"X-Dup: first\r\n"
        b"X-Dup: second\r\n"
        b"Authorization: Bearer top-secret-token\r\n"
        b"\r\n"
    )
    resp = heap.record(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 17\r\n"
        b"\r\n"
        b'{"ok":true,"n":1}'
    )
    unique_req = heap.record(
        b"POST /api/login HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 31\r\n"
        b"\r\n"
        b'{"username":"a","password":"b"}'
    )
    unique_resp = heap.record(
        b"HTTP/1.1 302 Found\r\n"
        b"Location: /home\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    repeater_req = heap.record(
        b"GET /repeater-only HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"\r\n"
    )
    repeater_resp = heap.record(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 2\r\n"
        b"\r\nOK"
    )
    collab_req = heap.record(
        b"GET /probe HTTP/1.1\r\n"
        b"Host: abcdefghijklmnop.oastify.com\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )
    collab_resp = heap.record(
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Burp Collaborator https://burpcollaborator.net/\r\n"
        b"Content-Length: 2\r\n"
        b"\r\nOK"
    )

    host_wrapper = heap.obj([(0, "addr", heap.text("example.test"))])
    service = heap.obj([
        (0, "addr", host_wrapper),
        (1, "i32", 443),
        (2, "u8", 1),
    ])
    metadata = heap.obj([(0, "addr", service)])
    comment = heap.obj([(0, "addr", heap.text("test note"))])

    proxy_row = heap.obj([
        (0, "i32", 42),
        (1, "addr", heap.immutable_string("GET")),
        (2, "addr", metadata),
        (3, "addr", comment),
        (4, "addr", heap.immutable_string("203.0.113.7")),
        (6, "i16", 200),
        (7, "i16", 0x0104),
        (8, "i32", 17),
        (9, "addr", heap.immutable_string("Test title")),
        (10, "addr", heap.immutable_string("sid=super-secret")),
        (11, "i64", 1700000000000),
        (13, "u8", 3),
        (14, "i32", 8080),
        (15, "addr", req),
        (18, "addr", resp),
    ], type_id=1)

    proxy = heap.obj([
        (0, "addr", heap.chunked_collection([proxy_row])),
    ])

    repeater_pair = heap.obj([(2, "addr", repeater_req), (3, "addr", repeater_resp)])
    repeater_tab = heap.obj([
        (0, "addr", heap.immutable_string("1")),
        (2, "addr", heap.direct_collection([repeater_pair])),
    ])
    repeater = heap.obj([
        (1, "addr", heap.direct_collection([repeater_tab])),
    ])

    # Site Map: one entry duplicates the Proxy exchange, one is unique.
    msg_duplicate = heap.obj([
        (0, "addr", req),
        (1, "addr", resp),
        (3, "i64", 1700000001000),
    ])
    msg_unique = heap.obj([
        (0, "addr", unique_req),
        (1, "addr", unique_resp),
        (3, "i64", 1700000002000),
    ])
    node_duplicate = heap.obj([(33, "addr", msg_duplicate)], type_id=3)
    node_unique = heap.obj([(33, "addr", msg_unique)], type_id=3)
    tuples = heap.array(
        struct.pack(">qqq", 0, node_duplicate, 0)
        + struct.pack(">qqq", 0, node_unique, 0),
        24,
    )
    bucket = heap.obj([(0, "i32", 2), (1, "addr", tuples)])
    buckets = heap.chunked_collection([bucket])
    index = heap.obj([(2, "i32", 2), (3, "addr", buckets)])
    target = heap.obj([(3, "addr", index)])

    project_name = heap.immutable_string("unit-test-project")
    root = heap.obj([
        (1, "addr", proxy),
        (2, "addr", repeater),
        (3, "addr", target),
        (6, "addr", project_name),
    ], subtype=6)

    data = heap.finish(root)
    with open(path, "wb") as handle:
        handle.write(data)
    return {
        "req": req,
        "resp": resp,
        "unique_req": unique_req,
        "unique_resp": unique_resp,
        "root": root,
        "collab_req": collab_req,
        "collab_resp": collab_resp,
    }


class HeapProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "fixture.burp")
        self.addresses = build_project(self.path)

    def _read(self):
        warnings = []
        raw, method, extra = b2j.read_burp(self.path, 200_000, warnings)
        merged = b2j.merge_exchanges(raw)
        items = b2j.finalize_items(merged, 200_000)
        return items, extra, warnings, method

    def test_heap_header_and_extraction(self):
        items, extra, warnings, method = self._read()
        self.assertEqual(method, "burp-heap")
        self.assertEqual(extra["header"]["schema_current"], 217)
        self.assertEqual(extra["project_name"], "unit-test-project")

        self.assertEqual(len(items), 3)
        proxy = next(item for item in items if item["source_tool"] == "proxy")
        self.assertEqual(proxy["method"], "GET")
        self.assertEqual(proxy["path"], "/api/items")
        self.assertEqual(proxy["host"], "example.test")
        self.assertEqual(proxy["port"], 443)
        self.assertEqual(proxy["protocol"], "https")
        self.assertEqual(proxy["status"], 200)
        self.assertEqual(proxy["comment"], "test note")
        self.assertEqual(proxy["highlight"], "yellow")
        self.assertEqual(proxy["time"], 1700000000000)
        self.assertEqual(proxy["metadata"]["burp_mime"], "JSON")
        self.assertEqual(proxy["metadata"]["cookie_header"], "sid=super-secret")
        self.assertEqual(proxy["also_seen_in"], ["site-map"])
        dup_headers = [h for h in proxy["request"]["headers"] if h[0].lower() == "x-dup"]
        self.assertEqual(dup_headers, [["X-Dup", "first"], ["X-Dup", "second"]])

        repeater = next(item for item in items if item["source_tool"] == "repeater")
        self.assertEqual(repeater["request"]["method"], "GET")
        self.assertEqual(repeater["metadata"]["tab"], "1")

        site_map = next(item for item in items if item["source_tool"] == "site-map")
        self.assertEqual(site_map["method"], "POST")
        self.assertEqual(site_map["status"], 302)
        self.assertEqual(site_map["time"], 1700000002000)
        self.assertEqual(site_map["request"]["body_params"],
                         [["username", "a"], ["password", "b"]])

        self.assertEqual(extra["coverage"]["proxy_items"], 1)
        self.assertEqual(extra["coverage"]["repeater_pairs"], 1)
        self.assertEqual(extra["coverage"]["site_map_messages"], 2)
        self.assertEqual(extra["coverage"]["collaborator_http_interactions"], 1)
        self.assertEqual(extra["coverage"]["unattributed_frames"], 0)
        self.assertEqual(extra["collaborator"]["domains_seen"],
                         ["abcdefghijklmnop.oastify.com"])
        self.assertEqual(len(extra["collaborator"]["interactions"]), 1)
        self.assertFalse([w for w in warnings if "unattributed" in w])

    def test_redaction(self):
        items, extra, _warnings, _method = self._read()
        b2j.redact_items(items)
        b2j.redact_collaborator(extra["collaborator"])
        text = json.dumps(items)
        self.assertNotIn("super-secret", text)
        self.assertNotIn("top-secret-token", text)
        proxy = next(item for item in items if item["source_tool"] == "proxy")
        self.assertEqual(proxy["metadata"]["cookie_header"], "[REDACTED]")
        self.assertEqual(proxy["request"]["cookies"], {"sid": "[REDACTED]"})
        headers = {name.lower(): value for name, value in proxy["request"]["headers"]}
        self.assertEqual(headers["cookie"], "[REDACTED]")
        self.assertEqual(headers["authorization"], "[REDACTED]")
        site_map = next(item for item in items if item["source_tool"] == "site-map")
        body_params = {key: value for key, value in site_map["request"]["body_params"]}
        self.assertEqual(body_params["password"], "[REDACTED]")

    def test_host_filter_and_chunking(self):
        out = os.path.join(self.tmp.name, "all.json")
        self.assertEqual(b2j.main([self.path, "-o", out, "--host", "example", "--max-body", "10"]), 0)
        with open(out, encoding="utf-8") as handle:
            doc = json.load(handle)
        self.assertEqual(doc["meta"]["item_count"], 3)
        self.assertEqual(doc["summary"]["hosts"], {"example.test": 3})
        self.assertTrue(any(item["request"]["body_truncated"] for item in doc["items"]))

        chunk_dir = os.path.join(self.tmp.name, "chunked.json")
        b2j.main([self.path, "-o", chunk_dir, "--chunk-items", "2", "--no-summary"])
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "chunked_part001.json")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "chunked_part002.json")))
        with open(os.path.join(self.tmp.name, "chunked_part001.json"), encoding="utf-8") as handle:
            part = json.load(handle)
        self.assertNotIn("summary", part)
        self.assertEqual(len(part["items"]), 2)

    def test_input_is_not_modified(self):
        with open(self.path, "rb") as handle:
            before = handle.read()
        warnings = []
        b2j.read_burp(self.path, 10_000, warnings)
        with open(self.path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)


class HttpParsingTests(unittest.TestCase):
    def test_chunked_and_compressed_bodies(self):
        body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        decoded, complete = b2j._decode_chunked(body)
        self.assertTrue(complete)
        self.assertEqual(decoded, b"Wikipedia")
        self.assertEqual(b2j._decompress(gzip.compress(b"hello"), "gzip")[0], b"hello")
        self.assertEqual(b2j._decompress(zlib.compress(b"hello"), "deflate")[0], b"hello")

    def test_body_encoding(self):
        self.assertEqual(b2j.encode_body(b"hello", 100)["body_encoding"], "utf-8")
        self.assertEqual(b2j.encode_body(b"\x00\x01\x02", 100)["body_encoding"], "base64")
        truncated = b2j.encode_body(b"abcdef", 3)
        self.assertEqual(truncated["body"], "abc")
        self.assertTrue(truncated["body_truncated"])
        self.assertEqual(truncated["body_length"], 6)

    def test_parse_http_duplicate_headers_and_json_params(self):
        raw = (b"POST /x?a=1&a=2 HTTP/1.1\r\nHost: h.test\r\n"
               b"Content-Type: application/json\r\nContent-Length: 20\r\n"
               b"X-A: 1\r\nX-A: 2\r\n\r\n{\"user\":\"bob\",\"n\":4}")
        parsed, consumed, warnings = b2j.parse_http(raw, True, 1000, strict_end=len(raw))
        self.assertEqual(consumed, len(raw))
        self.assertEqual(warnings, [])
        b2j.enrich_request(parsed)
        self.assertEqual(parsed["headers"].count(["X-A", "1"]), 1)
        self.assertEqual(parsed["headers"].count(["X-A", "2"]), 1)
        self.assertEqual(parsed["query_params"], [["a", "1"], ["a", "2"]])
        self.assertEqual(parsed["body_params"], [["user", "bob"], ["n", 4]])

    def test_absolute_url_inference(self):
        req = {"target": "https://example.test:8443/a?b=1", "headers": []}
        url, host, port, scheme = b2j._infer_url(req, {})
        self.assertEqual(url, "https://example.test:8443/a?b=1")
        self.assertEqual((host, port, scheme), ("example.test", 8443, "https"))


class XmlHarCarverTests(unittest.TestCase):
    def test_xml_export(self):
        xml = """<?xml version="1.0"?>
<items>
  <item>
    <time>2024-01-01T00:00:00Z</time>
    <url>https://example.test/a</url>
    <host ip="203.0.113.1">example.test</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/a</path>
    <request base64="true">%s</request>
    <status>200</status>
    <response base64="true">%s</response>
    <comment>review me</comment>
    <type>Proxy</type>
  </item>
</items>""" % (
            base64.b64encode(b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n").decode(),
            base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").decode(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "export.xml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(xml)
            warnings = []
            raw, method = b2j.read_xml(path, 10_000, warnings)
            items = b2j.finalize_items(raw, 10_000)
        self.assertEqual(method, "burp-xml")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_tool"], "proxy")
        self.assertEqual(items[0]["host"], "example.test")
        self.assertEqual(items[0]["status"], 200)
        self.assertEqual(items[0]["comment"], "review me")
        self.assertEqual(items[0]["response"]["body"], "OK")
        self.assertEqual(warnings, [])

    def test_har(self):
        har = {
            "log": {"entries": [{
                "startedDateTime": "2024-01-01T00:00:00Z",
                "request": {
                    "method": "POST",
                    "url": "https://example.test:8443/api",
                    "httpVersion": "HTTP/2",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {"mimeType": "application/json", "text": '{"a":1}'},
                },
                "response": {
                    "status": 201,
                    "statusText": "Created",
                    "httpVersion": "HTTP/2",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "content": {"mimeType": "application/json", "text": '{"ok":true}'},
                },
            }]}
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "export.har")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(har, handle)
            warnings = []
            raw, method = b2j.read_har(path, 10_000, warnings)
            items = b2j.finalize_items(raw, 10_000)
        self.assertEqual(method, "har")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["host"], "example.test")
        self.assertEqual(items[0]["port"], 8443)
        self.assertEqual(items[0]["protocol"], "https")
        self.assertEqual(items[0]["status"], 201)
        self.assertEqual(items[0]["request"]["body_params"], [["a", 1]])

    def test_fallback_carver_pairs_messages(self):
        raw = (
            b"\x00garbage\x00"
            b"GET /fallback HTTP/1.1\r\nHost: fallback.test\r\n\r\n"
            b"HTTP/1.1 204 No Content\r\n\r\n"
            b"tail"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "unknown.bin")
            with open(path, "wb") as handle:
                handle.write(raw)
            warnings = []
            items, method, extra = b2j.read_burp_fallback(path, 10_000, warnings)
        self.assertEqual(method, "frame-carver")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["request"]["target"], "/fallback")
        self.assertEqual(items[0]["response"]["status"], 204)
        self.assertEqual(extra["collaborator"]["domains_seen"], [])


class SummaryTests(unittest.TestCase):
    def test_summary(self):
        raw = (b"GET /b?z=1 HTTP/2\r\nHost: h.test\r\nAccept: */*\r\n\r\n")
        parsed = b2j.parse_http(raw, True, 1000, strict_end=len(raw))[0]
        resp = b2j.parse_http(b"HTTP/2 500 Oops\r\nContent-Type: text/html\r\n\r\nx",
                              False, 1000, strict_end=53)[0]
        item = {
            "id": 1, "source_tool": "proxy", "host": "h.test", "port": 443,
            "protocol": "https", "url": "https://h.test/b?z=1",
            "highlight": "red", "request": parsed, "response": resp,
        }
        b2j.enrich_request(item["request"])
        summary = b2j.build_summary([item])
        self.assertEqual(summary["total_items"], 1)
        self.assertEqual(summary["hosts"], {"h.test": 1})
        self.assertEqual(summary["methods"], {"GET": 1})
        self.assertEqual(summary["status_codes"], {"500": 1})
        self.assertEqual(summary["server_errors"][0]["status"], 500)
        self.assertEqual(summary["highlights"], {"red": 1})


REAL_SAMPLE = os.path.join(ROOT, "2026-10-22-burp2jsonew.burp")


@unittest.skipUnless(os.path.exists(REAL_SAMPLE), "real .burp sample is not present")
class RealSampleTests(unittest.TestCase):
    def test_real_sample(self):
        warnings = []
        raw, method, extra = b2j.read_burp(REAL_SAMPLE, 200_000, warnings)
        items = b2j.finalize_items(b2j.merge_exchanges(raw), 200_000)
        self.assertEqual(method, "burp-heap")
        self.assertGreaterEqual(len(items), 90)
        self.assertEqual({item["protocol"] for item in items}, {"https"})
        self.assertEqual({item["host"] for item in items}, {"chatgpt.com"})
        self.assertTrue(any(item["comment"] == "js" for item in items))
        self.assertGreaterEqual(len(extra["collaborator"]["interactions"]), 1)
        self.assertEqual(extra["coverage"]["unattributed_frames"], 242)


if __name__ == "__main__":
    unittest.main()

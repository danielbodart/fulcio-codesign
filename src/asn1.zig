// asn1.zig — Minimal ASN.1 DER builder for PKCS#10 CSR construction
//
// Builds raw DER bytes in a fixed buffer. No allocations.

const std = @import("std");

pub const Builder = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Builder {
        return .{ .buf = buf };
    }

    pub fn output(self: *const Builder) []const u8 {
        return self.buf[0..self.pos];
    }

    // Write raw bytes
    pub fn raw(self: *Builder, data: []const u8) void {
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    pub fn byte(self: *Builder, b: u8) void {
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    // Write a DER tag + length prefix, then call inner to write contents.
    // Uses a two-pass approach: first pass measures, second pass writes.
    pub fn tagged(self: *Builder, tag: u8, inner: anytype) void {
        // Save position, write placeholder, run inner to measure
        const start = self.pos;
        inner.write(self);
        const content_len = self.pos - start;

        // Shift content to make room for tag + length
        const header_len = 1 + lengthOfLength(content_len);
        std.mem.copyBackwards(u8, self.buf[start + header_len ..], self.buf[start .. start + content_len]);

        // Write tag + length at start
        var p = start;
        self.buf[p] = tag;
        p += 1;
        p += writeLength(self.buf[p..], content_len);
        self.pos = start + header_len + content_len;
    }

    fn lengthOfLength(len: usize) usize {
        if (len < 128) return 1;
        if (len < 256) return 2;
        if (len < 65536) return 3;
        return 4;
    }

    fn writeLength(buf: []u8, len: usize) usize {
        if (len < 128) {
            buf[0] = @intCast(len);
            return 1;
        }
        if (len < 256) {
            buf[0] = 0x81;
            buf[1] = @intCast(len);
            return 2;
        }
        if (len < 65536) {
            buf[0] = 0x82;
            buf[1] = @intCast(len >> 8);
            buf[2] = @intCast(len & 0xFF);
            return 3;
        }
        buf[0] = 0x83;
        buf[1] = @intCast(len >> 16);
        buf[2] = @intCast((len >> 8) & 0xFF);
        buf[3] = @intCast(len & 0xFF);
        return 4;
    }
};

// ─── DER primitives ────────────────────────────────────────────────────────

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0C;

pub fn integer(b: *Builder, value: u8) void {
    b.byte(INTEGER);
    b.byte(1);
    b.byte(value);
}

pub fn oid(b: *Builder, encoded: []const u8) void {
    b.byte(OID);
    b.byte(@intCast(encoded.len));
    b.raw(encoded);
}

pub fn bitString(b: *Builder, data: []const u8) void {
    b.byte(BIT_STRING);
    const bs_len = 1 + data.len;
    if (bs_len < 128) {
        b.byte(@intCast(bs_len));
    } else {
        b.byte(0x81);
        b.byte(@intCast(bs_len));
    }
    b.byte(0x00); // no unused bits
    b.raw(data);
}

pub fn utf8String(b: *Builder, s: []const u8) void {
    b.byte(UTF8_STRING);
    // Use proper length encoding for longer strings
    if (s.len < 128) {
        b.byte(@intCast(s.len));
    } else {
        b.byte(0x81);
        b.byte(@intCast(s.len));
    }
    b.raw(s);
}

// Common OIDs
pub const oid_cn = &[_]u8{ 0x55, 0x04, 0x03 }; // 2.5.4.3 — commonName
pub const oid_o = &[_]u8{ 0x55, 0x04, 0x0A }; // 2.5.4.10 — organizationName
pub const oid_ec_pub_key = &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 }; // 1.2.840.10045.2.1
pub const oid_prime256v1 = &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
pub const oid_ecdsa_sha256 = &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 }; // 1.2.840.10045.4.3.2

// ─── Tests ─────────────────────────────────────────────────────────────────

test "integer zero" {
    var buf: [10]u8 = undefined;
    var b = Builder.init(&buf);
    integer(&b, 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x01, 0x00 }, b.output());
}

test "oid commonName" {
    var buf: [10]u8 = undefined;
    var b = Builder.init(&buf);
    oid(&b, oid_cn);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 }, b.output());
}

test "tagged sequence" {
    var buf: [20]u8 = undefined;
    var b = Builder.init(&buf);
    b.tagged(SEQUENCE, struct {
        pub fn write(_: *const @This(), inner: *Builder) void {
            integer(inner, 42);
        }
    }{});
    // SEQUENCE { INTEGER 42 }
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x2A }, b.output());
}

test "utf8 string" {
    var buf: [20]u8 = undefined;
    var b = Builder.init(&buf);
    utf8String(&b, "test");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0C, 0x04, 't', 'e', 's', 't' }, b.output());
}

test "nested sequences" {
    // SEQUENCE { SEQUENCE { INTEGER 1 }, SEQUENCE { INTEGER 2 } }
    var buf: [30]u8 = undefined;
    var b = Builder.init(&buf);
    b.tagged(SEQUENCE, struct {
        pub fn write(_: *const @This(), outer: *Builder) void {
            outer.tagged(SEQUENCE, struct {
                pub fn write(_: *const @This(), inner: *Builder) void {
                    integer(inner, 1);
                }
            }{});
            outer.tagged(SEQUENCE, struct {
                pub fn write(_: *const @This(), inner: *Builder) void {
                    integer(inner, 2);
                }
            }{});
        }
    }{});
    const out = b.output();
    // Outer: 30 0C (12 bytes)
    //   Inner1: 30 03 02 01 01
    //   Inner2: 30 03 02 01 02
    try std.testing.expectEqual(@as(u8, SEQUENCE), out[0]);
    try std.testing.expectEqual(@as(u8, 10), out[1]); // 5 + 5 = 10 bytes
    // First inner sequence
    try std.testing.expectEqual(@as(u8, SEQUENCE), out[2]);
    try std.testing.expectEqual(@as(u8, 3), out[3]);
    try std.testing.expectEqual(@as(u8, 1), out[6]); // INTEGER value
    // Second inner sequence
    try std.testing.expectEqual(@as(u8, SEQUENCE), out[7]);
    try std.testing.expectEqual(@as(u8, 3), out[8]);
    try std.testing.expectEqual(@as(u8, 2), out[11]); // INTEGER value
}

test "empty sequence" {
    var buf: [10]u8 = undefined;
    var b = Builder.init(&buf);
    b.tagged(SEQUENCE, struct {
        pub fn write(_: *const @This(), _: *Builder) void {}
    }{});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x00 }, b.output());
}

test "set with oid and string" {
    // SET { SEQUENCE { OID cn, UTF8String "hello" } }
    var buf: [30]u8 = undefined;
    var b = Builder.init(&buf);
    b.tagged(SET, struct {
        pub fn write(_: *const @This(), inner: *Builder) void {
            inner.tagged(SEQUENCE, struct {
                pub fn write(_: *const @This(), seq: *Builder) void {
                    oid(seq, oid_cn);
                    utf8String(seq, "hello");
                }
            }{});
        }
    }{});
    const out = b.output();
    try std.testing.expectEqual(@as(u8, SET), out[0]);
    // Verify OID cn bytes are present
    try std.testing.expect(std.mem.indexOf(u8, out, &[_]u8{ 0x55, 0x04, 0x03 }) != null);
    // Verify "hello" is present
    try std.testing.expect(std.mem.indexOf(u8, out, "hello") != null);
}

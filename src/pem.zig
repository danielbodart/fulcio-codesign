// pem.zig — PEM encoding/decoding
//
// Wraps DER bytes in PEM format (base64 with 64-char lines and header/footer).
// Decodes PEM back to DER for certificate import.

const std = @import("std");
const base64 = std.base64.standard;

/// PEM-encode DER bytes with the given label (e.g., "CERTIFICATE REQUEST").
pub fn encode(allocator: std.mem.Allocator, label: []const u8, der: []const u8) ![]u8 {
    const b64_len = base64.Encoder.calcSize(der.len);
    const b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);
    const b64 = base64.Encoder.encode(b64_buf, der);

    // Calculate total size: header + base64 with line breaks + footer
    const num_lines = (b64.len + 63) / 64;
    const header = "-----BEGIN -----\n";
    const footer = "-----END -----\n";
    const total = header.len + label.len + footer.len + label.len + b64.len + num_lines;

    var result = try allocator.alloc(u8, total);
    var pos: usize = 0;

    // Header: "-----BEGIN <label>-----\n"
    pos += write(result[pos..], "-----BEGIN ");
    pos += write(result[pos..], label);
    pos += write(result[pos..], "-----\n");

    // Base64 body with line breaks every 64 chars
    var i: usize = 0;
    while (i < b64.len) {
        const chunk = @min(64, b64.len - i);
        @memcpy(result[pos..][0..chunk], b64[i..][0..chunk]);
        pos += chunk;
        result[pos] = '\n';
        pos += 1;
        i += chunk;
    }

    // Footer: "-----END <label>-----\n"
    pos += write(result[pos..], "-----END ");
    pos += write(result[pos..], label);
    pos += write(result[pos..], "-----\n");

    return allocator.realloc(result, pos) catch result[0..pos];
}

/// Decode PEM to DER bytes. Strips header/footer and decodes the base64 body.
pub fn decode(allocator: std.mem.Allocator, pem_data: []const u8) ![]u8 {
    const header_end = std.mem.indexOf(u8, pem_data, "\n") orelse return error.InvalidPEM;
    const footer_marker = "-----END ";
    const footer_start = std.mem.lastIndexOf(u8, pem_data, footer_marker) orelse return error.InvalidPEM;

    if (footer_start <= header_end + 1) return error.InvalidPEM;

    const b64_body = std.mem.trim(u8, pem_data[header_end + 1 .. footer_start], &std.ascii.whitespace);

    const decoder = base64.decoderWithIgnore("\n\r ");
    const max_len = try decoder.calcSizeUpperBound(b64_body.len);
    const dest = try allocator.alloc(u8, max_len);
    const actual_len = try decoder.decode(dest, b64_body);
    return allocator.realloc(dest, actual_len) catch dest[0..actual_len];
}

fn write(dest: []u8, src: []const u8) usize {
    @memcpy(dest[0..src.len], src);
    return src.len;
}

// ─── Tests ─────────────────────────────────────────────────────────────────

test "pem encode small" {
    const allocator = std.testing.allocator;
    const der = "hello";
    const pem = try encode(allocator, "TEST", der);
    defer allocator.free(pem);

    try std.testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN TEST-----\n"));
    try std.testing.expect(std.mem.endsWith(u8, pem, "-----END TEST-----\n"));
    // Base64 of "hello" is "aGVsbG8="
    try std.testing.expect(std.mem.indexOf(u8, pem, "aGVsbG8=") != null);
}

test "pem encode line wrapping" {
    const allocator = std.testing.allocator;
    // 48 bytes of DER -> 64 chars of base64 -> exactly one line
    const der = [_]u8{0xAB} ** 48;
    const pem = try encode(allocator, "DATA", &der);
    defer allocator.free(pem);

    // Should have header, one 64-char line, footer
    var lines = std.mem.splitScalar(u8, pem, '\n');
    const header = lines.next().?;
    try std.testing.expectEqualStrings("-----BEGIN DATA-----", header);
    const b64_line = lines.next().?;
    try std.testing.expectEqual(@as(usize, 64), b64_line.len);
    const footer = lines.next().?;
    try std.testing.expectEqualStrings("-----END DATA-----", footer);
}

test "pem encode multi-line" {
    const allocator = std.testing.allocator;
    // 49 bytes -> 68 chars base64 -> two lines (64 + 4)
    const der = [_]u8{0xCD} ** 49;
    const pem = try encode(allocator, "CERT", &der);
    defer allocator.free(pem);

    var lines = std.mem.splitScalar(u8, pem, '\n');
    _ = lines.next(); // header
    const line1 = lines.next().?;
    try std.testing.expectEqual(@as(usize, 64), line1.len);
    const line2 = lines.next().?;
    try std.testing.expect(line2.len > 0);
    try std.testing.expect(line2.len <= 64);
}

test "pem decode" {
    const allocator = std.testing.allocator;
    const pem_text =
        \\-----BEGIN TEST-----
        \\aGVsbG8=
        \\-----END TEST-----
    ;
    const der = try decode(allocator, pem_text);
    defer allocator.free(der);
    try std.testing.expectEqualStrings("hello", der);
}

test "pem decode multi-line base64" {
    const allocator = std.testing.allocator;
    // "The quick brown fox" base64 = "VGhlIHF1aWNrIGJyb3duIGZveA=="
    const pem_text = "-----BEGIN DATA-----\nVGhlIHF1aWNr\nIGJyb3duIGZveA==\n-----END DATA-----\n";
    const der = try decode(allocator, pem_text);
    defer allocator.free(der);
    try std.testing.expectEqualStrings("The quick brown fox", der);
}

test "pem decode invalid - no header" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidPEM, decode(allocator, "no header here"));
}

test "pem encode-decode roundtrip" {
    const allocator = std.testing.allocator;
    const original = [_]u8{ 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09 };
    const pem_text = try encode(allocator, "CERTIFICATE", &original);
    defer allocator.free(pem_text);
    const decoded = try decode(allocator, pem_text);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &original, decoded);
}

test "pem roundtrip with std decoder" {
    const allocator = std.testing.allocator;
    const original = "The quick brown fox jumps over the lazy dog";
    const pem = try encode(allocator, "MESSAGE", original);
    defer allocator.free(pem);

    // Extract base64 between header and footer
    const header_end = std.mem.indexOf(u8, pem, "\n").? + 1;
    const footer_start = std.mem.lastIndexOf(u8, pem[0 .. pem.len - 1], "\n-----END").?;
    const b64_with_newlines = pem[header_end..footer_start];

    // Decode using std, ignoring newlines
    const decoder = std.base64.standard.decoderWithIgnore("\n");
    const decoded_len = try decoder.calcSizeUpperBound(b64_with_newlines.len);
    var decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    const actual_len = try decoder.decode(decoded, b64_with_newlines);
    try std.testing.expectEqualStrings(original, decoded[0..actual_len]);
}

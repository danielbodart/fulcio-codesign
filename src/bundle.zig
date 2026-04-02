// bundle.zig — Sigstore bundle JSON output
//
// Writes the Fulcio certificate chain and raw response as a JSON bundle
// that can be used for out-of-band verification.

const std = @import("std");
const Stringify = std.json.Stringify;

/// Write a Sigstore verification bundle to the given path.
/// Contains the Fulcio certificate chain for offline verification.
pub fn writeBundle(
    allocator: std.mem.Allocator,
    path: []const u8,
    chain_pems: []const []const u8,
    fulcio_response: []const u8,
) !void {
    var alloc_writer = try std.Io.Writer.Allocating.initCapacity(allocator, 4096);
    defer alloc_writer.deinit();

    var stream: Stringify = .{
        .writer = &alloc_writer.writer,
        .options = .{ .whitespace = .indent_2 },
    };

    try stream.beginObject();

    try stream.objectField("mediaType");
    try stream.write("application/vnd.dev.sigstore.bundle.v0.3+json");

    try stream.objectField("verificationMaterial");
    try stream.beginObject();

    try stream.objectField("certificates");
    try stream.beginArray();
    for (chain_pems) |cert_pem| {
        try stream.beginObject();
        try stream.objectField("rawBytes");
        try stream.write(cert_pem);
        try stream.endObject();
    }
    try stream.endArray();

    try stream.endObject(); // verificationMaterial

    try stream.objectField("fulcioResponse");
    // Parse and re-emit the raw Fulcio JSON to get proper formatting
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        fulcio_response,
        .{},
    ) catch {
        // If parsing fails, write as a raw string
        try stream.write(fulcio_response);
        try stream.endObject();
        return writeToFile(path, alloc_writer.writer.buffer[0..alloc_writer.writer.end]);
    };
    defer parsed.deinit();
    try stream.write(parsed.value);

    try stream.endObject();

    try writeToFile(path, alloc_writer.writer.buffer[0..alloc_writer.writer.end]);
}

fn writeToFile(path: []const u8, data: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(data);
    try file.writeAll("\n");
}

// ─── Tests ─────────────────────────────────────────────────────────────────

test "writeBundle creates valid JSON" {
    const allocator = std.testing.allocator;

    const chain = &[_][]const u8{
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
    };
    const response = "{\"test\": true}";

    const path = "/tmp/fulcio-codesign-test-bundle.json";
    try writeBundle(allocator, path, chain, response);
    defer std.fs.cwd().deleteFile(path) catch {};

    // Read back and verify it's valid JSON
    const contents = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    defer allocator.free(contents);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, contents, .{});
    defer parsed.deinit();

    // Verify structure
    const obj = parsed.value.object;
    try std.testing.expect(obj.contains("mediaType"));
    try std.testing.expect(obj.contains("verificationMaterial"));
    try std.testing.expect(obj.contains("fulcioResponse"));
}

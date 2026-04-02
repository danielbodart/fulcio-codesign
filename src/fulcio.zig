// fulcio.zig — OIDC token fetching and Fulcio API client
//
// Handles:
// 1. GitHub Actions OIDC token acquisition (CI)
// 2. Certificate signing request to Fulcio's /api/v2/signingCert
// 3. Response parsing to extract the certificate chain

const std = @import("std");
const http = std.http;

const log = std.log.scoped(.fulcio);

pub const CertChain = struct {
    leaf_pem: []const u8,
    chain_pems: []const []const u8,
    raw_response: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *CertChain) void {
        self.allocator.free(self.leaf_pem);
        for (self.chain_pems) |p| self.allocator.free(p);
        self.allocator.free(self.chain_pems);
        self.allocator.free(self.raw_response);
    }
};

/// Fetch OIDC token from GitHub Actions environment.
pub fn fetchGitHubOIDCToken(allocator: std.mem.Allocator) ![]u8 {
    const request_url = std.posix.getenv("ACTIONS_ID_TOKEN_REQUEST_URL") orelse
        return error.NoGitHubOIDCEnv;
    const request_token = std.posix.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") orelse
        return error.NoGitHubOIDCEnv;

    const url = try std.fmt.allocPrint(allocator, "{s}&audience=sigstore", .{request_url});
    defer allocator.free(url);

    const auth_value = try std.fmt.allocPrint(allocator, "Bearer {s}", .{request_token});
    defer allocator.free(auth_value);

    const body = try httpGet(allocator, url, auth_value);
    defer allocator.free(body);

    // Parse JSON response: { "value": "<token>" }
    const parsed = std.json.parseFromSlice(
        struct { value: []const u8 },
        allocator,
        body,
        .{ .ignore_unknown_fields = true },
    ) catch |e| {
        log.err("failed to parse GitHub OIDC response: {}", .{e});
        return error.OIDCParseFailed;
    };
    defer parsed.deinit();

    return allocator.dupe(u8, parsed.value.value);
}

/// Request a certificate from Fulcio.
pub fn requestCertificate(
    allocator: std.mem.Allocator,
    fulcio_url: []const u8,
    csr_pem: []const u8,
    oidc_token: []const u8,
) !CertChain {
    // Base64-encode the CSR PEM for JSON transport
    const b64 = std.base64.standard;
    const b64_len = b64.Encoder.calcSize(csr_pem.len);
    const b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);
    const csr_b64 = b64.Encoder.encode(b64_buf, csr_pem);

    // Build JSON request body
    const request_body = try std.fmt.allocPrint(allocator,
        \\{{"credentials":{{"oidcIdentityToken":"{s}"}},"certificateSigningRequest":"{s}"}}
    , .{ oidc_token, csr_b64 });
    defer allocator.free(request_body);

    const url = try std.fmt.allocPrint(allocator, "{s}/api/v2/signingCert", .{fulcio_url});
    defer allocator.free(url);

    const response_body = try httpPost(allocator, url, "application/json", request_body);
    defer allocator.free(response_body);

    return parseFulcioResponse(allocator, response_body);
}

/// Parse the Fulcio signingCert response to extract the certificate chain.
pub fn parseFulcioResponse(allocator: std.mem.Allocator, body: []const u8) !CertChain {
    const parsed = std.json.parseFromSlice(FulcioResponse, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return error.FulcioParseFailed;
    };
    defer parsed.deinit();

    const chain_obj = if (parsed.value.signedCertificateEmbeddedSct) |sct|
        sct
    else if (parsed.value.signedCertificateDetachedSct) |sct|
        sct
    else
        return error.NoCertificateChain;

    const certs = chain_obj.chain.certificates;
    if (certs.len == 0) return error.EmptyCertificateChain;

    const leaf_pem = try allocator.dupe(u8, certs[0]);

    const chain_pems = try allocator.alloc([]const u8, certs.len);
    for (certs, 0..) |cert, i| {
        chain_pems[i] = try allocator.dupe(u8, cert);
    }

    return .{
        .leaf_pem = leaf_pem,
        .chain_pems = chain_pems,
        .raw_response = try allocator.dupe(u8, body),
        .allocator = allocator,
    };
}

const FulcioResponse = struct {
    signedCertificateEmbeddedSct: ?SignedCert = null,
    signedCertificateDetachedSct: ?SignedCert = null,
};

const SignedCert = struct {
    chain: Chain,
};

const Chain = struct {
    certificates: []const []const u8,
};

// ─── HTTP helpers ──────────────────────────────────────────────────────────

fn httpGet(allocator: std.mem.Allocator, url: []const u8, auth_header: []const u8) ![]u8 {
    var client: http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);

    var req = try client.request(.GET, uri, .{
        .extra_headers = &.{
            .{ .name = "Authorization", .value = auth_header },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var header_buf: [8192]u8 = undefined;
    var response = try req.receiveHead(&header_buf);

    if (response.head.status != .ok) {
        log.err("HTTP GET {s}: status {}", .{ url, response.head.status });
        return error.HttpRequestFailed;
    }

    return readResponseBody(allocator, &response);
}

fn httpPost(allocator: std.mem.Allocator, url: []const u8, content_type: []const u8, payload: []const u8) ![]u8 {
    var client: http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);

    var req = try client.request(.POST, uri, .{
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = content_type },
        },
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = payload.len };
    var send_buf: [1]u8 = undefined;
    var body_writer = try req.sendBodyUnflushed(&send_buf);
    try body_writer.writer.writeAll(payload);
    try body_writer.end();
    try req.connection.?.flush();

    var header_buf: [8192]u8 = undefined;
    var response = try req.receiveHead(&header_buf);

    if (response.head.status != .ok) {
        log.err("HTTP POST {s}: status {}", .{ url, response.head.status });
        const err_body = readResponseBody(allocator, &response) catch |e| {
            log.err("could not read error body: {}", .{e});
            return error.HttpRequestFailed;
        };
        defer allocator.free(err_body);
        if (err_body.len > 0) {
            log.err("Response: {s}", .{err_body});
        }
        return error.HttpRequestFailed;
    }

    return readResponseBody(allocator, &response);
}

fn readResponseBody(allocator: std.mem.Allocator, response: *http.Client.Response) ![]u8 {
    var transfer_buf: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buf);

    var body: std.ArrayListUnmanaged(u8) = .{};
    errdefer body.deinit(allocator);

    var read_buf: [4096]u8 = undefined;
    while (true) {
        const n = reader.readSliceShort(&read_buf) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
        };
        if (n == 0) break;
        try body.appendSlice(allocator, read_buf[0..n]);
    }

    return body.toOwnedSlice(allocator);
}

// ─── Tests ─────────────────────────────────────────────────────────────────

test "parse fulcio response with embedded SCT" {
    const allocator = std.testing.allocator;
    const resp_body =
        \\{"signedCertificateEmbeddedSct":{"chain":{"certificates":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"]}}}
    ;
    var chain = try parseFulcioResponse(allocator, resp_body);
    defer chain.deinit();

    try std.testing.expectEqual(@as(usize, 2), chain.chain_pems.len);
    try std.testing.expect(std.mem.startsWith(u8, chain.leaf_pem, "-----BEGIN CERTIFICATE-----"));
}

test "parse fulcio response with detached SCT" {
    const allocator = std.testing.allocator;
    const resp_body =
        \\{"signedCertificateDetachedSct":{"chain":{"certificates":["-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"]}}}
    ;
    var chain = try parseFulcioResponse(allocator, resp_body);
    defer chain.deinit();

    try std.testing.expectEqual(@as(usize, 1), chain.chain_pems.len);
}

test "parse fulcio response empty chain fails" {
    const allocator = std.testing.allocator;
    const resp_body =
        \\{"signedCertificateEmbeddedSct":{"chain":{"certificates":[]}}}
    ;
    try std.testing.expectError(error.EmptyCertificateChain, parseFulcioResponse(allocator, resp_body));
}

test "parse fulcio response no chain fails" {
    const allocator = std.testing.allocator;
    const resp_body = "{}";
    try std.testing.expectError(error.NoCertificateChain, parseFulcioResponse(allocator, resp_body));
}

// main.zig — fulcio-codesign CLI entry point
//
// Signs a macOS binary using a Fulcio certificate obtained via OIDC.
// Replaces the bash script with a single binary that uses Security.framework
// directly (no openssl, curl, jq, security, or codesign dependencies).
//
// Usage:
//   fulcio-codesign --identifier <id> [options] <binary>
//
// In CI (GitHub Actions), OIDC token is fetched automatically.
// Locally, pass --token <token> or --token - (stdin).

const std = @import("std");
const crypto = @import("crypto.zig");
const fulcio = @import("fulcio.zig");
const keychain = @import("keychain.zig");
const signer = @import("signer.zig");
const bundle = @import("bundle.zig");
const pem = @import("pem.zig");
const sec = @import("security.zig");

const log = std.log.scoped(.@"fulcio-codesign");

const Args = struct {
    identifier: [:0]const u8,
    entitlements_path: ?[]const u8 = null,
    requirement: ?[:0]const u8 = null,
    subject: ?[]const u8 = null,
    token: ?[]const u8 = null,
    fulcio_url: []const u8 = "https://fulcio.sigstore.dev",
    bundle_path: ?[]const u8 = null,
    binary_path: [:0]const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = parseArgs() catch |err| {
        if (err == error.HelpRequested) std.process.exit(0);
        std.process.exit(1);
    };

    run(allocator, args) catch |err| {
        log.err("fatal: {}", .{err});
        std.process.exit(1);
    };
}

fn run(allocator: std.mem.Allocator, args: Args) !void {
    // Step 1: Get OIDC token
    log.info("obtaining OIDC token...", .{});
    const oidc_token = try getOIDCToken(allocator, args.token);
    defer allocator.free(oidc_token);
    log.info("OIDC token obtained ({d} bytes)", .{oidc_token.len});

    // Step 2: Create temp keychain (needed before key generation)
    log.info("creating temporary keychain...", .{});
    var kc = try keychain.TempKeychain.create();
    defer kc.deinit();
    try kc.addToSearchList();

    // Step 3: Generate EC P-256 key pair directly in the temp keychain
    log.info("generating ephemeral key pair...", .{});
    const key_pair = try crypto.generateKeyPair(kc.keychain);
    defer key_pair.deinit();

    // Step 4: Build CSR
    const subject = args.subject orelse args.identifier;
    log.info("building CSR (subject: {s})...", .{subject});
    const csr_pem = try crypto.buildCSR(allocator, key_pair, subject);
    defer allocator.free(csr_pem);

    // Step 5: Request certificate from Fulcio
    log.info("requesting certificate from Fulcio ({s})...", .{args.fulcio_url});
    var cert_chain = try fulcio.requestCertificate(allocator, args.fulcio_url, csr_pem, oidc_token);
    defer cert_chain.deinit();
    log.info("certificate received ({d} certs in chain)", .{cert_chain.chain_pems.len});

    // Step 6: Import certs into keychain
    log.info("importing certificates...", .{});
    const leaf_der = try pem.decode(allocator, cert_chain.leaf_pem);
    defer allocator.free(leaf_der);
    const leaf_cert = try kc.importCert(leaf_der);
    defer sec.CFRelease(@ptrCast(leaf_cert));

    for (cert_chain.chain_pems[1..]) |cert_pem| {
        const der = try pem.decode(allocator, cert_pem);
        defer allocator.free(der);
        const cert = try kc.importCert(der);
        sec.CFRelease(@ptrCast(cert));
    }

    // Step 7: Create identity (links key + cert)
    log.info("creating signing identity...", .{});
    const identity = try kc.createIdentity(leaf_cert);
    defer sec.CFRelease(@ptrCast(identity));

    // Step 7: Read entitlements if provided
    var entitlements_data: ?[]u8 = null;
    defer if (entitlements_data) |d| allocator.free(d);
    if (args.entitlements_path) |path| {
        entitlements_data = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
            log.err("failed to read entitlements file '{s}': {}", .{ path, err });
            return error.EntitlementsReadFailed;
        };
    }

    // Step 8: Build designated requirement
    const default_req_tmp = try std.fmt.allocPrint(allocator, "designated => identifier \"{s}\"", .{args.identifier});
    defer allocator.free(default_req_tmp);
    const default_req = try allocator.dupeZ(u8, default_req_tmp);
    defer allocator.free(default_req);
    const requirement: [:0]const u8 = args.requirement orelse default_req;

    // Step 9: Sign the binary
    log.info("signing {s}...", .{args.binary_path});
    try signer.signBinary(allocator, args.binary_path, .{
        .identity = identity,
        .identifier = args.identifier,
        .entitlements = entitlements_data,
        .requirement = requirement,
    });
    log.info("binary signed successfully", .{});

    // Step 10: Write bundle if requested
    if (args.bundle_path) |bp| {
        log.info("writing bundle to {s}...", .{bp});
        try bundle.writeBundle(allocator, bp, cert_chain.chain_pems, cert_chain.raw_response);
        log.info("bundle written", .{});
    }
}

// ─── OIDC token resolution ─────────────────────────────────────────────────

fn getOIDCToken(allocator: std.mem.Allocator, token_arg: ?[]const u8) ![]u8 {
    // 1. Explicit --token flag
    if (token_arg) |t| {
        if (std.mem.eql(u8, t, "-")) {
            // Read from stdin
            const stdin = std.fs.File.stdin();
            var buf: [8192]u8 = undefined;
            var total: usize = 0;
            while (true) {
                const n = stdin.read(buf[total..]) catch break;
                if (n == 0) break;
                total += n;
            }
            const trimmed = std.mem.trim(u8, buf[0..total], &std.ascii.whitespace);
            return allocator.dupe(u8, trimmed);
        }
        return allocator.dupe(u8, t);
    }

    // 2. FULCIO_TOKEN env var
    if (std.posix.getenv("FULCIO_TOKEN")) |t| {
        return allocator.dupe(u8, t);
    }

    // 3. GitHub Actions OIDC
    if (std.posix.getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != null) {
        return fulcio.fetchGitHubOIDCToken(allocator);
    }

    log.err("no OIDC token available", .{});
    log.err("use --token <token>, --token - (stdin), FULCIO_TOKEN env, or run in GitHub Actions", .{});
    return error.NoOIDCToken;
}

// ─── CLI argument parsing ──────────────────────────────────────────────────

fn parseArgs() !Args {
    var arg_iter = std.process.args();
    _ = arg_iter.skip(); // skip argv[0]

    var identifier: ?[:0]const u8 = null;
    var entitlements_path: ?[]const u8 = null;
    var requirement: ?[:0]const u8 = null;
    var subject: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var fulcio_url: []const u8 = "https://fulcio.sigstore.dev";
    var bundle_path: ?[]const u8 = null;
    var binary_path: ?[:0]const u8 = null;

    while (arg_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return error.HelpRequested;
        } else if (std.mem.eql(u8, arg, "--identifier")) {
            identifier = arg_iter.next() orelse {
                log.err("--identifier requires a value", .{});
                return error.MissingArgValue;
            };
        } else if (std.mem.eql(u8, arg, "--entitlements")) {
            entitlements_path = arg_iter.next() orelse {
                log.err("--entitlements requires a value", .{});
                return error.MissingArgValue;
            };
        } else if (std.mem.eql(u8, arg, "--requirement")) {
            requirement = arg_iter.next() orelse {
                log.err("--requirement requires a value", .{});
                return error.MissingArgValue;
            };
        } else if (std.mem.eql(u8, arg, "--subject")) {
            subject = arg_iter.next() orelse {
                log.err("--subject requires a value", .{});
                return error.MissingArgValue;
            };
        } else if (std.mem.eql(u8, arg, "--token")) {
            token = arg_iter.next() orelse {
                log.err("--token requires a value", .{});
                return error.MissingArgValue;
            };
        } else if (std.mem.eql(u8, arg, "--fulcio-url")) {
            fulcio_url = arg_iter.next() orelse {
                log.err("--fulcio-url requires a value", .{});
                return error.MissingArgValue;
            };
        } else if (std.mem.eql(u8, arg, "--bundle")) {
            bundle_path = arg_iter.next() orelse {
                log.err("--bundle requires a value", .{});
                return error.MissingArgValue;
            };
        } else if (arg[0] == '-') {
            log.err("unknown option: {s}", .{arg});
            return error.UnknownOption;
        } else {
            binary_path = arg;
        }
    }

    if (identifier == null) {
        log.err("--identifier is required", .{});
        printUsage();
        return error.MissingRequiredArg;
    }

    if (binary_path == null) {
        log.err("binary path is required", .{});
        printUsage();
        return error.MissingRequiredArg;
    }

    return .{
        .identifier = identifier.?,
        .entitlements_path = entitlements_path,
        .requirement = requirement,
        .subject = subject,
        .token = token,
        .fulcio_url = fulcio_url,
        .bundle_path = bundle_path,
        .binary_path = binary_path.?,
    };
}

fn printUsage() void {
    const stderr = std.fs.File.stderr();
    stderr.writeAll(
        \\Usage: fulcio-codesign [options] <binary>
        \\
        \\Sign a macOS binary using a Fulcio certificate.
        \\
        \\Required:
        \\  --identifier <id>       Code signing identifier (e.g., com.example.app)
        \\
        \\Options:
        \\  --entitlements <path>   Entitlements plist file
        \\  --requirement <text>    Designated requirement (default: identifier "<id>")
        \\  --subject <text>        CSR subject CN (default: identifier value)
        \\  --token <token | ->     OIDC token (- reads from stdin)
        \\  --fulcio-url <url>      Fulcio server (default: https://fulcio.sigstore.dev)
        \\  --bundle <path>         Write Sigstore bundle JSON to path
        \\  --help, -h              Show this help
        \\
        \\OIDC token resolution (in order):
        \\  1. --token flag
        \\  2. FULCIO_TOKEN environment variable
        \\  3. GitHub Actions OIDC (automatic in CI)
        \\
    ) catch {};
}

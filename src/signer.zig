// signer.zig — SecCodeSigner SPI wrapper for macOS code signing
//
// Uses SecCodeSignerCreate + SecCodeSignerAddSignatureWithErrors,
// the same SPI that /usr/bin/codesign calls internally.

const std = @import("std");
const sec = @import("security.zig");

pub const SigningOptions = struct {
    identity: sec.SecIdentityRef,
    identifier: [:0]const u8,
    entitlements: ?[]const u8 = null, // plist XML data
    requirement: ?[:0]const u8 = null, // DR text
    hardened_runtime: bool = true,
    timestamp: bool = true,
    force: bool = true,
};

/// Wrap entitlements XML plist in an EntitlementBlob header (magic 0xfade7171).
/// The SecCodeSigner SPI expects entitlements as CFData containing this blob format,
/// not raw XML. See Apple's security_codesigning/sigblob.h: Blob<EntitlementBlob, 0xfade7171>.
fn makeEntitlementBlob(allocator: std.mem.Allocator, xml_data: []const u8) ![]u8 {
    const total_len: u32 = @intCast(8 + xml_data.len);
    var blob = try allocator.alloc(u8, total_len);
    // Magic: 0xfade7171 (big-endian)
    blob[0] = 0xfa;
    blob[1] = 0xde;
    blob[2] = 0x71;
    blob[3] = 0x71;
    // Length: total blob size including header (big-endian)
    blob[4] = @intCast((total_len >> 24) & 0xFF);
    blob[5] = @intCast((total_len >> 16) & 0xFF);
    blob[6] = @intCast((total_len >> 8) & 0xFF);
    blob[7] = @intCast(total_len & 0xFF);
    // Payload: XML plist
    @memcpy(blob[8..], xml_data);
    return blob;
}

pub fn signBinary(allocator: std.mem.Allocator, binary_path: [:0]const u8, opts: SigningOptions) !void {
    // Create static code reference for the binary
    const url = sec.CFURLCreateFromFileSystemRepresentation(
        null,
        binary_path.ptr,
        @intCast(binary_path.len),
        0, // not a directory
    ) orelse return error.URLCreateFailed;
    defer sec.CFRelease(@ptrCast(url));

    var static_code: ?sec.SecStaticCodeRef = null;
    try sec.checkOSStatus(
        sec.SecStaticCodeCreateWithPath(@ptrCast(url), 0, &static_code),
        "SecStaticCodeCreateWithPath",
    );
    defer sec.CFRelease(@ptrCast(static_code.?));

    // Build signing parameters dictionary
    const params = sec.createMutableDict();
    defer sec.CFRelease(@ptrCast(params));

    // Identity (private key + certificate)
    sec.CFDictionarySetValue(params, sec.kSecCodeSignerIdentity, @ptrCast(opts.identity));

    // Identifier string
    const id_str = sec.cfStr(opts.identifier);
    defer sec.CFRelease(@ptrCast(id_str));
    sec.CFDictionarySetValue(params, sec.kSecCodeSignerIdentifier, @ptrCast(id_str));

    // CodeDirectory flags (e.g., hardened runtime)
    if (opts.hardened_runtime) {
        const flags: u32 = sec.kSecCodeSignatureRuntime;
        const flags_num = sec.CFNumberCreate(null, sec.kCFNumberSInt32Type, &flags) orelse
            return error.CFNumberCreateFailed;
        defer sec.CFRelease(@ptrCast(flags_num));
        sec.CFDictionarySetValue(params, sec.kSecCodeSignerFlags, @ptrCast(flags_num));
    }

    // Timestamp
    if (opts.timestamp) {
        sec.CFDictionarySetValue(params, sec.kSecCodeSignerRequireTimestamp, @ptrCast(sec.kCFBooleanTrue));
    }

    // Entitlements: wrap XML plist in EntitlementBlob (magic 0xfade7171 header)
    if (opts.entitlements) |ent_data| {
        const blob = try makeEntitlementBlob(allocator, ent_data);
        defer allocator.free(blob);
        const cf_ent = sec.cfData(blob);
        defer sec.CFRelease(@ptrCast(cf_ent));
        sec.CFDictionarySetValue(params, sec.kSecCodeSignerEntitlements, @ptrCast(cf_ent));
    }

    // Designated requirement (text)
    if (opts.requirement) |req_text| {
        const req_str = sec.cfStr(req_text);
        defer sec.CFRelease(@ptrCast(req_str));
        sec.CFDictionarySetValue(params, sec.kSecCodeSignerRequirements, @ptrCast(req_str));
    }

    // Create the signer (force flag = replace existing signature)
    const signer_flags: u32 = if (opts.force) sec.kSecCodeSignatureForce else 0;
    var signer: ?sec.SecCodeSignerRef = null;
    try sec.checkOSStatus(
        sec.SecCodeSignerCreate(@ptrCast(params), signer_flags, &signer),
        "SecCodeSignerCreate",
    );
    defer sec.CFRelease(@ptrCast(signer.?));

    // Sign the binary
    var sign_err: ?sec.CFErrorRef = null;
    const sign_status = sec.SecCodeSignerAddSignatureWithErrors(signer.?, static_code.?, 0, &sign_err);
    if (sign_status != 0) {
        if (sign_err) |e| {
            defer sec.CFRelease(@ptrCast(e));
            sec.logCFError("SecCodeSignerAddSignatureWithErrors", e);
        }
        std.log.err("SecCodeSignerAddSignatureWithErrors: OSStatus {d}", .{sign_status});
        return error.SigningFailed;
    }
}

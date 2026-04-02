// keychain.zig — Temporary keychain management
//
// Creates a temporary keychain, imports certificates, and manages the
// keychain search list so the CMS encoder can find the full cert chain
// when building the code signature.

const std = @import("std");
const sec = @import("security.zig");

pub const TempKeychain = struct {
    keychain: sec.SecKeychainRef,
    path_buf: [256]u8,
    path_len: usize,
    original_search_list: ?sec.CFArrayRef = null,

    pub fn create() !TempKeychain {
        // Generate a unique keychain path in /tmp
        var path_buf: [256]u8 = undefined;
        const template = "/tmp/fulcio-codesign-XXXXXXXX.keychain-db";
        @memcpy(path_buf[0..template.len], template);

        // Replace X's with random hex chars
        var prng = std.Random.DefaultPrng.init(@truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
        const random = prng.random();
        const x_start = std.mem.indexOf(u8, &path_buf, "XXXXXXXX").?;
        for (path_buf[x_start..][0..8]) |*c| {
            c.* = "0123456789abcdef"[random.intRangeAtMost(u4, 0, 15)];
        }
        const path_len = template.len;
        path_buf[path_len] = 0; // null-terminate

        // Random password for the keychain
        var password: [16]u8 = undefined;
        for (&password) |*c| {
            c.* = "abcdefghijklmnopqrstuvwxyz0123456789"[random.intRangeAtMost(u8, 0, 35)];
        }

        var keychain: ?sec.SecKeychainRef = null;
        try sec.checkOSStatus(
            sec.SecKeychainCreate(
                @ptrCast(&path_buf),
                password.len,
                &password,
                0, // don't prompt user
                null, // default access
                &keychain,
            ),
            "SecKeychainCreate",
        );

        // Unlock it
        try sec.checkOSStatus(
            sec.SecKeychainUnlock(keychain.?, password.len, &password, 1),
            "SecKeychainUnlock",
        );

        return .{
            .keychain = keychain.?,
            .path_buf = path_buf,
            .path_len = path_len,
        };
    }

    /// Add the temp keychain to the user keychain search list.
    /// The CMS encoder uses the search list to build the certificate chain
    /// when creating the code signature. Without this, it can't find the
    /// Sigstore root CA and fails with "unable to build chain to self-signed root".
    pub fn addToSearchList(self: *TempKeychain) !void {
        // Save current search list
        var current_list: ?sec.CFArrayRef = null;
        try sec.checkOSStatus(
            sec.SecKeychainCopySearchList(&current_list),
            "SecKeychainCopySearchList",
        );
        self.original_search_list = current_list;

        // Create a mutable copy and prepend our keychain
        const new_list = sec.CFArrayCreateMutableCopy(null, 0, current_list.?) orelse
            return error.CFArrayCreateFailed;
        sec.CFArrayInsertValueAtIndex(new_list, 0, @ptrCast(self.keychain));

        try sec.checkOSStatus(
            sec.SecKeychainSetSearchList(@ptrCast(new_list)),
            "SecKeychainSetSearchList",
        );
        sec.CFRelease(@ptrCast(new_list));
    }

    /// Import a DER certificate into the keychain. Returns the SecCertificateRef.
    pub fn importCert(self: *TempKeychain, cert_der: []const u8) !sec.SecCertificateRef {
        const cert_data = sec.cfData(cert_der);
        defer sec.CFRelease(@ptrCast(cert_data));

        // Create SecCertificateRef
        const cert = sec.SecCertificateCreateWithData(null, cert_data) orelse
            return error.CertificateCreateFailed;

        // Import into keychain
        var format: sec.SecExternalFormat = sec.kSecFormatUnknown;
        var item_type: sec.SecExternalItemType = sec.kSecItemTypeUnknown;
        var items: ?sec.CFArrayRef = null;

        try sec.checkOSStatus(
            sec.SecItemImport(
                cert_data,
                null,
                &format,
                &item_type,
                0,
                null,
                self.keychain,
                &items,
            ),
            "SecItemImport (cert)",
        );
        if (items) |i| sec.CFRelease(@ptrCast(i));

        return cert;
    }

    /// Create a SecIdentityRef from a certificate in the keychain
    pub fn createIdentity(self: *TempKeychain, cert: sec.SecCertificateRef) !sec.SecIdentityRef {
        var identity: ?sec.SecIdentityRef = null;
        try sec.checkOSStatus(
            sec.SecIdentityCreateWithCertificate(@ptrCast(self.keychain), cert, &identity),
            "SecIdentityCreateWithCertificate",
        );
        return identity.?;
    }

    pub fn deinit(self: *TempKeychain) void {
        // Restore original keychain search list
        if (self.original_search_list) |list| {
            _ = sec.SecKeychainSetSearchList(list);
            sec.CFRelease(@ptrCast(list));
        }
        _ = sec.SecKeychainDelete(self.keychain);
        sec.CFRelease(@ptrCast(self.keychain));
    }
};

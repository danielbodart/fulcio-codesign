// crypto.zig — EC P-256 key generation and PKCS#10 CSR construction
//
// Uses Security.framework for key generation and signing.
// Builds the CSR as raw ASN.1 DER (no openssl dependency).

const std = @import("std");
const sec = @import("security.zig");
const asn1 = @import("asn1.zig");
const pem = @import("pem.zig");

pub const KeyPair = struct {
    private_key: sec.SecKeyRef,
    public_key: sec.SecKeyRef,

    pub fn deinit(self: KeyPair) void {
        sec.CFRelease(@ptrCast(self.private_key));
        sec.CFRelease(@ptrCast(self.public_key));
    }
};

/// Generate an EC P-256 key pair. If keychain is provided, the key is created
/// directly in that keychain (permanent). Otherwise it's ephemeral (in-memory).
pub fn generateKeyPair(keychain: ?sec.SecKeychainRef) !KeyPair {
    const params = sec.createMutableDict();
    defer sec.CFRelease(@ptrCast(params));

    sec.CFDictionarySetValue(params, sec.kSecAttrKeyType, sec.kSecAttrKeyTypeECSECPrimeRandom);
    const bits: i32 = 256;
    const bits_num = sec.CFNumberCreate(null, sec.kCFNumberSInt32Type, &bits) orelse
        return error.CFNumberCreateFailed;
    defer sec.CFRelease(@ptrCast(bits_num));
    sec.CFDictionarySetValue(params, sec.kSecAttrKeySizeInBits, @ptrCast(bits_num));

    if (keychain) |kc| {
        sec.CFDictionarySetValue(params, sec.kSecAttrIsPermanent, @ptrCast(sec.kCFBooleanTrue));
        sec.CFDictionarySetValue(params, sec.kSecUseKeychain, @ptrCast(kc));
    } else {
        sec.CFDictionarySetValue(params, sec.kSecAttrIsPermanent, @ptrCast(sec.kCFBooleanFalse));
    }

    var err: ?sec.CFErrorRef = null;
    const private_key = sec.SecKeyCreateRandomKey(@ptrCast(params), &err) orelse {
        if (err) |e| {
            defer sec.CFRelease(@ptrCast(e));
            sec.logCFError("SecKeyCreateRandomKey", e);
        }
        return error.KeyGenerationFailed;
    };

    const public_key = sec.SecKeyCopyPublicKey(private_key) orelse {
        sec.CFRelease(@ptrCast(private_key));
        return error.PublicKeyCopyFailed;
    };

    return .{ .private_key = private_key, .public_key = public_key };
}

/// Sign data with the private key using ECDSA-SHA256
fn signData(private_key: sec.SecKeyRef, data: []const u8) !struct { sig_data: sec.CFDataRef } {
    const cf_data = sec.cfData(data);
    defer sec.CFRelease(@ptrCast(cf_data));

    var err: ?sec.CFErrorRef = null;
    const sig = sec.SecKeyCreateSignature(
        private_key,
        sec.kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        cf_data,
        &err,
    ) orelse {
        if (err) |e| {
            defer sec.CFRelease(@ptrCast(e));
            sec.logCFError("SecKeyCreateSignature", e);
        }
        return error.SigningFailed;
    };
    return .{ .sig_data = sig };
}

/// Build a PKCS#10 CSR as PEM-encoded string.
/// Subject contains CN=<subject> (single RDN).
pub fn buildCSR(
    allocator: std.mem.Allocator,
    key_pair: KeyPair,
    subject: []const u8,
) ![]u8 {
    // Get public key bytes
    var pub_key_err: ?sec.CFErrorRef = null;
    const pub_data = sec.SecKeyCopyExternalRepresentation(key_pair.public_key, &pub_key_err) orelse {
        if (pub_key_err) |e| {
            defer sec.CFRelease(@ptrCast(e));
            sec.logCFError("SecKeyCopyExternalRepresentation", e);
        }
        return error.PublicKeyExportFailed;
    };
    defer sec.CFRelease(@ptrCast(pub_data));
    const pub_key_bytes = sec.CFDataGetBytePtr(pub_data)[0..@intCast(sec.CFDataGetLength(pub_data))];

    // Build CertificationRequestInfo (the TBS portion)
    var tbs_buf: [1024]u8 = undefined;
    var tbs = asn1.Builder.init(&tbs_buf);
    tbs.tagged(asn1.SEQUENCE, CertReqInfo{ .subject = subject, .pub_key_bytes = pub_key_bytes });
    const tbs_bytes = tbs.output();

    // Sign the CertificationRequestInfo
    const sig_result = try signData(key_pair.private_key, tbs_bytes);
    defer sec.CFRelease(@ptrCast(sig_result.sig_data));
    const sig_bytes = sec.CFDataGetBytePtr(sig_result.sig_data)[0..@intCast(sec.CFDataGetLength(sig_result.sig_data))];

    // Build the full CSR: SEQUENCE { tbs, signatureAlgorithm, signature }
    var csr_buf: [2048]u8 = undefined;
    var csr = asn1.Builder.init(&csr_buf);
    csr.tagged(asn1.SEQUENCE, CSRWrapper{ .tbs_bytes = tbs_bytes, .sig_bytes = sig_bytes });
    const csr_der = csr.output();

    // PEM-encode
    return pem.encode(allocator, "CERTIFICATE REQUEST", csr_der);
}

// ─── ASN.1 structure builders ──────────────────────────────────────────────

const CertReqInfo = struct {
    subject: []const u8,
    pub_key_bytes: []const u8,

    pub fn write(self: *const CertReqInfo, b: *asn1.Builder) void {
        // version INTEGER 0
        asn1.integer(b, 0);

        // subject: SEQUENCE { SET { SEQUENCE { OID cn, UTF8String subject } } }
        b.tagged(asn1.SEQUENCE, SubjectRDN{ .subject = self.subject });

        // subjectPublicKeyInfo: SEQUENCE { algorithm, BIT STRING pubkey }
        b.tagged(asn1.SEQUENCE, SubjectPubKeyInfo{ .pub_key_bytes = self.pub_key_bytes });

        // attributes [0] IMPLICIT (empty — no extensions)
        b.byte(0xA0);
        b.byte(0x00);
    }
};

const SubjectRDN = struct {
    subject: []const u8,

    pub fn write(self: *const SubjectRDN, b: *asn1.Builder) void {
        b.tagged(asn1.SET, RDNAttr{ .oid_bytes = asn1.oid_cn, .value = self.subject });
    }
};

const RDNAttr = struct {
    oid_bytes: []const u8,
    value: []const u8,

    pub fn write(self: *const RDNAttr, b: *asn1.Builder) void {
        b.tagged(asn1.SEQUENCE, AttrInner{ .oid_bytes = self.oid_bytes, .value = self.value });
    }
};

const AttrInner = struct {
    oid_bytes: []const u8,
    value: []const u8,

    pub fn write(self: *const AttrInner, b: *asn1.Builder) void {
        asn1.oid(b, self.oid_bytes);
        asn1.utf8String(b, self.value);
    }
};

const SubjectPubKeyInfo = struct {
    pub_key_bytes: []const u8,

    pub fn write(self: *const SubjectPubKeyInfo, b: *asn1.Builder) void {
        // AlgorithmIdentifier: SEQUENCE { OID ecPublicKey, OID prime256v1 }
        b.tagged(asn1.SEQUENCE, AlgorithmId{});

        asn1.bitString(b, self.pub_key_bytes);
    }
};

const AlgorithmId = struct {
    pub fn write(_: *const AlgorithmId, b: *asn1.Builder) void {
        asn1.oid(b, asn1.oid_ec_pub_key);
        asn1.oid(b, asn1.oid_prime256v1);
    }
};

const CSRWrapper = struct {
    tbs_bytes: []const u8,
    sig_bytes: []const u8,

    pub fn write(self: *const CSRWrapper, b: *asn1.Builder) void {
        // CertificationRequestInfo (already DER-encoded)
        b.raw(self.tbs_bytes);

        // SignatureAlgorithm: SEQUENCE { OID ecdsaWithSHA256 }
        b.tagged(asn1.SEQUENCE, SigAlg{});

        asn1.bitString(b, self.sig_bytes);
    }
};

const SigAlg = struct {
    pub fn write(_: *const SigAlg, b: *asn1.Builder) void {
        asn1.oid(b, asn1.oid_ecdsa_sha256);
    }
};

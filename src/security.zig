// security.zig — Security.framework and CoreFoundation extern declarations
//
// All macOS Security/CoreFoundation symbols used by fulcio-codesign.
// SPI symbols (SecCodeSigner*) are exported from Security.framework
// but not in public headers.

const std = @import("std");

// ─── CoreFoundation opaque types ───────────────────────────────────────────

// We always pass null for CFAllocatorRef (kCFAllocatorDefault).
pub const CFTypeRef = *anyopaque;
pub const CFStringRef = *anyopaque;
pub const CFDataRef = *anyopaque;
pub const CFDictionaryRef = *anyopaque;
pub const CFMutableDictionaryRef = *anyopaque;
pub const CFArrayRef = *anyopaque;
pub const CFNumberRef = *anyopaque;
pub const CFBooleanRef = *anyopaque;
pub const CFErrorRef = *anyopaque;
pub const CFURLRef = *anyopaque;

pub const CFIndex = isize;
pub const CFStringEncoding = u32;
pub const Boolean = u8;
pub const OSStatus = i32;
pub const SecKeychainRef = *anyopaque;
pub const SecKeyRef = *anyopaque;
pub const SecCertificateRef = *anyopaque;
pub const SecIdentityRef = *anyopaque;
pub const SecStaticCodeRef = *anyopaque;
pub const SecCodeSignerRef = *anyopaque;
pub const SecExternalFormat = u32;
pub const SecExternalItemType = u32;
pub const SecItemImportExportKeyParameters = extern struct {
    version: u32 = 0,
    flags: u32 = 0,
    passphrase: ?CFTypeRef = null,
    alert_title: ?CFStringRef = null,
    alert_prompt: ?CFStringRef = null,
    access_ref: ?*anyopaque = null,
    key_usage: ?*anyopaque = null,
    key_attributes: ?CFArrayRef = null,
};

pub const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;
pub const kSecFormatUnknown: SecExternalFormat = 0;
pub const kSecItemTypeUnknown: SecExternalItemType = 0;

// ─── CoreFoundation functions ──────────────────────────────────────────────

pub extern "c" fn CFRelease(cf: CFTypeRef) void;
pub extern "c" fn CFRetain(cf: CFTypeRef) CFTypeRef;

pub extern "c" fn CFStringCreateWithCString(alloc: ?*anyopaque, cstr: [*:0]const u8, encoding: CFStringEncoding) ?CFStringRef;
pub extern "c" fn CFStringGetCStringPtr(str: CFStringRef, encoding: CFStringEncoding) ?[*:0]const u8;
pub extern "c" fn CFStringGetCString(str: CFStringRef, buf: [*]u8, buf_size: CFIndex, encoding: CFStringEncoding) Boolean;

pub extern "c" fn CFDataCreate(alloc: ?*anyopaque, bytes: [*]const u8, length: CFIndex) ?CFDataRef;
pub extern "c" fn CFDataGetBytePtr(data: CFDataRef) [*]const u8;
pub extern "c" fn CFDataGetLength(data: CFDataRef) CFIndex;

pub extern "c" fn CFDictionaryCreateMutable(alloc: ?*anyopaque, capacity: CFIndex, key_callbacks: ?*const anyopaque, value_callbacks: ?*const anyopaque) ?CFMutableDictionaryRef;
pub extern "c" fn CFDictionarySetValue(dict: CFMutableDictionaryRef, key: *const anyopaque, value: *const anyopaque) void;

pub extern "c" fn CFArrayGetCount(array: CFArrayRef) CFIndex;
pub extern "c" fn CFArrayGetValueAtIndex(array: CFArrayRef, idx: CFIndex) ?CFTypeRef;

pub extern "c" fn CFNumberCreate(alloc: ?*anyopaque, the_type: CFIndex, value_ptr: *const anyopaque) ?CFNumberRef;

pub extern "c" fn CFURLCreateFromFileSystemRepresentation(alloc: ?*anyopaque, buf: [*]const u8, buf_len: CFIndex, is_directory: Boolean) ?CFURLRef;

pub extern "c" fn CFErrorCopyDescription(err: CFErrorRef) ?CFStringRef;

// kCFTypeDictionaryKeyCallBacks and kCFTypeDictionaryValueCallBacks
pub extern "c" var kCFTypeDictionaryKeyCallBacks: anyopaque;
pub extern "c" var kCFTypeDictionaryValueCallBacks: anyopaque;
pub extern "c" var kCFBooleanTrue: CFBooleanRef;
pub extern "c" var kCFBooleanFalse: CFBooleanRef;

// ─── Security.framework: Key generation ────────────────────────────────────

pub extern "c" fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, err: *?CFErrorRef) ?SecKeyRef;
pub extern "c" fn SecKeyCopyPublicKey(key: SecKeyRef) ?SecKeyRef;
pub extern "c" fn SecKeyCopyExternalRepresentation(key: SecKeyRef, err: *?CFErrorRef) ?CFDataRef;
pub extern "c" fn SecKeyCreateSignature(key: SecKeyRef, algorithm: *const anyopaque, data: CFDataRef, err: *?CFErrorRef) ?CFDataRef;

// Key type and algorithm constants (pointers to CFStringRef)
pub extern "c" var kSecAttrKeyTypeECSECPrimeRandom: *const anyopaque;
pub extern "c" var kSecAttrKeyType: *const anyopaque;
pub extern "c" var kSecAttrKeySizeInBits: *const anyopaque;
pub extern "c" var kSecAttrIsPermanent: *const anyopaque;
pub extern "c" var kSecKeyAlgorithmECDSASignatureMessageX962SHA256: *const anyopaque;
pub extern "c" var kSecUseKeychain: *const anyopaque;

// ─── Security.framework: Certificates ──────────────────────────────────────

pub extern "c" fn SecCertificateCreateWithData(alloc: ?*anyopaque, data: CFDataRef) ?SecCertificateRef;

// ─── Security.framework: Keychain ──────────────────────────────────────────

pub extern "c" fn SecKeychainCreate(path: [*:0]const u8, password_len: u32, password: [*]const u8, prompt_user: Boolean, access: ?*anyopaque, keychain: *?SecKeychainRef) OSStatus;
pub extern "c" fn SecKeychainDelete(keychain: SecKeychainRef) OSStatus;
pub extern "c" fn SecKeychainUnlock(keychain: SecKeychainRef, password_len: u32, password: [*]const u8, use_password: Boolean) OSStatus;
pub extern "c" fn SecKeychainOpen(path: [*:0]const u8, keychain: *?SecKeychainRef) OSStatus;
pub extern "c" fn SecKeychainCopySearchList(search_list: *?CFArrayRef) OSStatus;
pub extern "c" fn SecKeychainSetSearchList(search_list: CFArrayRef) OSStatus;

// CFArray helpers for building search lists
pub extern "c" fn CFArrayCreateMutableCopy(alloc: ?*anyopaque, capacity: CFIndex, array: CFArrayRef) ?*anyopaque;
pub extern "c" fn CFArrayInsertValueAtIndex(array: *anyopaque, idx: CFIndex, value: *const anyopaque) void;

pub extern "c" fn SecItemImport(
    import_data: CFDataRef,
    file_name_or_ext: ?CFStringRef,
    input_format: *SecExternalFormat,
    item_type: *SecExternalItemType,
    flags: u32,
    key_params: ?*const SecItemImportExportKeyParameters,
    keychain: ?SecKeychainRef,
    out_items: *?CFArrayRef,
) OSStatus;

// ─── Security.framework: Identity ──────────────────────────────────────────

pub extern "c" fn SecIdentityCreateWithCertificate(keychain: ?SecKeychainRef, cert: SecCertificateRef, identity: *?SecIdentityRef) OSStatus;

// ─── Security.framework: Code Signing SPI ──────────────────────────────────

// These symbols are exported from Security.framework but not in public headers.
// They have been stable since macOS 10.5 (2007) and are what /usr/bin/codesign uses.

pub extern "c" fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: u32, static_code: *?SecStaticCodeRef) OSStatus;

pub extern "c" fn SecCodeSignerCreate(parameters: CFDictionaryRef, flags: u32, signer: *?SecCodeSignerRef) OSStatus;

pub extern "c" fn SecCodeSignerAddSignatureWithErrors(signer: SecCodeSignerRef, code: SecStaticCodeRef, flags: u32, errors: *?CFErrorRef) OSStatus;

// SPI parameter keys (exported as CFStringRef constants)
pub extern "c" var kSecCodeSignerIdentity: *const anyopaque;
pub extern "c" var kSecCodeSignerIdentifier: *const anyopaque;
pub extern "c" var kSecCodeSignerRequirements: *const anyopaque;
pub extern "c" var kSecCodeSignerEntitlements: *const anyopaque;
pub extern "c" var kSecCodeSignerFlags: *const anyopaque;
pub extern "c" var kSecCodeSignerTimestampAuthentication: *const anyopaque;
pub extern "c" var kSecCodeSignerRequireTimestamp: *const anyopaque;

// kSecCSSigningInformation for SecCodeCopySigningInformation
pub const kSecCSSigningInformation: u32 = 0x2;
pub const kSecCSInternalInformation: u32 = 0x1;

pub extern "c" fn SecCodeCopySigningInformation(code: SecStaticCodeRef, flags: u32, info: *?CFDictionaryRef) OSStatus;

// CFDictionary lookup
pub extern "c" fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const anyopaque) ?*const anyopaque;

// CFPropertyList
pub const CFPropertyListFormat = CFIndex;
pub const kCFPropertyListXMLFormat_v1_0: CFPropertyListFormat = 100;
pub extern "c" fn CFPropertyListCreateWithData(alloc: ?*anyopaque, data: CFDataRef, options: u64, format: ?*CFPropertyListFormat, error_out: ?*?CFErrorRef) ?CFTypeRef;

// Hardened runtime flag for SecCodeSignerFlags
pub const kSecCodeSignatureRuntime: u32 = 0x10000;
pub const kSecCodeSignatureForce: u32 = 0x10;

// CFNumber type
pub const kCFNumberSInt32Type: CFIndex = 3;

// ─── Helpers ───────────────────────────────────────────────────────────────

pub fn cfStr(s: [*:0]const u8) CFStringRef {
    return CFStringCreateWithCString(null, s, kCFStringEncodingUTF8) orelse
        @panic("CFStringCreateWithCString returned null");
}

pub fn cfData(bytes: []const u8) CFDataRef {
    return CFDataCreate(null, bytes.ptr, @intCast(bytes.len)) orelse
        @panic("CFDataCreate returned null");
}

/// Log a CFError description. The description is only valid for the duration of this call.
pub fn logCFError(context: []const u8, err: CFErrorRef) void {
    const desc = CFErrorCopyDescription(err) orelse {
        std.log.err("{s}: unknown error", .{context});
        return;
    };
    defer CFRelease(@ptrCast(desc));
    var buf: [256]u8 = undefined;
    if (CFStringGetCString(desc, &buf, buf.len, kCFStringEncodingUTF8) != 0) {
        std.log.err("{s}: {s}", .{ context, @as([*:0]const u8, @ptrCast(&buf)) });
    } else {
        std.log.err("{s}: (error description too long)", .{context});
    }
}

pub fn createMutableDict() CFMutableDictionaryRef {
    return CFDictionaryCreateMutable(null, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) orelse
        @panic("CFDictionaryCreateMutable returned null");
}

pub fn checkOSStatus(status: OSStatus, context: []const u8) !void {
    if (status != 0) {
        std.log.err("{s}: OSStatus {d}", .{ context, status });
        return error.SecurityFrameworkError;
    }
}

//go:build darwin

package enclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// generateSecureEnclaveKey creates an ECDSA P-256 key pair in the Secure Enclave.
// biometricPolicy: 0 = none, 1 = any (UserPresence), 2 = fingerprint (BiometryCurrentSet)
// On success, returns the SecKeyRef for the private key via *outKey and 0.
// On failure, returns non-zero and writes an error description to errBuf.
static int generateSecureEnclaveKey(const char *tag, int tagLen, int biometricPolicy, SecKeyRef *outKey, char *errBuf, int errBufLen) {
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    // Key type: EC P-256
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    int keySizeBits = 256;
    CFNumberRef keySize = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keySizeBits);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, keySize);

    // Secure Enclave token
    CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);

    // Access control — required for Secure Enclave keys
    // Determine flags based on biometric policy
    SecAccessControlCreateFlags acFlags;
    if (biometricPolicy == 0) {
        acFlags = kSecAccessControlPrivateKeyUsage;
    } else if (biometricPolicy == 2) {
        acFlags = kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet;
    } else {
        // Default: require user presence (fail-closed)
        acFlags = kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence;
    }

    CFErrorRef acError = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        acFlags,
        &acError);
    if (access == NULL) {
        if (acError != NULL) {
            CFStringRef desc = CFErrorCopyDescription(acError);
            CFStringGetCString(desc, errBuf, errBufLen, kCFStringEncodingUTF8);
            CFRelease(desc);
            CFRelease(acError);
        } else {
            snprintf(errBuf, errBufLen, "failed to create access control");
        }
        CFRelease(keySize);
        CFRelease(attrs);
        return -1;
    }

    // Private key attributes
    CFMutableDictionaryRef privateAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(privateAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(privateAttrs, kSecAttrAccessControl, access);

    CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tag, tagLen);
    CFDictionarySetValue(privateAttrs, kSecAttrApplicationTag, tagData);

    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, privateAttrs);

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey(attrs, &error);

    CFRelease(access);
    CFRelease(tagData);
    CFRelease(privateAttrs);
    CFRelease(keySize);
    CFRelease(attrs);

    if (privateKey == NULL) {
        if (error != NULL) {
            CFStringRef desc = CFErrorCopyDescription(error);
            CFStringGetCString(desc, errBuf, errBufLen, kCFStringEncodingUTF8);
            CFRelease(desc);
            CFRelease(error);
        } else {
            snprintf(errBuf, errBufLen, "unknown error creating key");
        }
        return -1;
    }

    *outKey = privateKey;
    return 0;
}

// extractPublicKeyBytes extracts the uncompressed EC point from a private key.
// Returns 0 on success, -1 on failure.
static int extractPublicKeyBytes(SecKeyRef privateKey, void **outBytes, int *outLen, char *errBuf, int errBufLen) {
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (publicKey == NULL) {
        snprintf(errBuf, errBufLen, "failed to copy public key");
        return -1;
    }

    CFErrorRef error = NULL;
    CFDataRef pubData = SecKeyCopyExternalRepresentation(publicKey, &error);
    CFRelease(publicKey);

    if (pubData == NULL) {
        if (error != NULL) {
            CFStringRef desc = CFErrorCopyDescription(error);
            CFStringGetCString(desc, errBuf, errBufLen, kCFStringEncodingUTF8);
            CFRelease(desc);
            CFRelease(error);
        } else {
            snprintf(errBuf, errBufLen, "failed to export public key");
        }
        return -1;
    }

    CFIndex len = CFDataGetLength(pubData);
    void *buf = malloc(len);
    if (buf == NULL) {
        CFRelease(pubData);
        snprintf(errBuf, errBufLen, "malloc failed for public key");
        return -1;
    }
    memcpy(buf, CFDataGetBytePtr(pubData), len);
    CFRelease(pubData);

    *outBytes = buf;
    *outLen = (int)len;
    return 0;
}

// lookupKey finds an existing private key by application tag.
// Returns 0 on success (key found), -1 on failure (not found or error).
static int lookupKey(const char *tag, int tagLen, SecKeyRef *outKey, char *errBuf, int errBufLen) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

    CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tag, tagLen);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    CFRelease(tagData);
    CFRelease(query);

    if (status != errSecSuccess) {
        snprintf(errBuf, errBufLen, "key not found (OSStatus %d)", (int)status);
        return -1;
    }

    *outKey = (SecKeyRef)result;
    return 0;
}

// deleteKey deletes ALL keys (private and public) matching the application tag.
// Loops until no more keys are found, to handle duplicate keys
// from repeated init runs.
// Returns 0 on success, -1 on failure.
static int deleteKey(const char *tag, int tagLen, char *errBuf, int errBufLen) {
    CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tag, tagLen);

    while (1) {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        CFDictionarySetValue(query, kSecClass, kSecClassKey);
        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
        CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);

        OSStatus status = SecItemDelete(query);
        CFRelease(query);

        if (status == errSecItemNotFound) {
            break;
        }
        if (status != errSecSuccess) {
            CFRelease(tagData);
            snprintf(errBuf, errBufLen, "failed to delete key (OSStatus %d)", (int)status);
            return -1;
        }
    }

    CFRelease(tagData);
    return 0;
}

// signData signs data using the private key identified by tag.
// Returns 0 on success, -1 on failure.
static int signData(SecKeyRef privateKey, const void *data, int dataLen, void **outSig, int *outSigLen, char *errBuf, int errBufLen) {
    CFDataRef dataRef = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)data, dataLen);

    CFErrorRef error = NULL;
    CFDataRef signature = SecKeyCreateSignature(privateKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, dataRef, &error);
    CFRelease(dataRef);

    if (signature == NULL) {
        if (error != NULL) {
            CFStringRef desc = CFErrorCopyDescription(error);
            CFStringGetCString(desc, errBuf, errBufLen, kCFStringEncodingUTF8);
            CFRelease(desc);
            CFRelease(error);
        } else {
            snprintf(errBuf, errBufLen, "failed to sign data");
        }
        return -1;
    }

    CFIndex len = CFDataGetLength(signature);
    void *buf = malloc(len);
    if (buf == NULL) {
        CFRelease(signature);
        snprintf(errBuf, errBufLen, "malloc failed for signature");
        return -1;
    }
    memcpy(buf, CFDataGetBytePtr(signature), len);
    CFRelease(signature);

    *outSig = buf;
    *outSigLen = (int)len;
    return 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// cgoBackend implements keyBackend using macOS Security framework via CGO.
type cgoBackend struct{}

func newPlatformEnclave() Enclave {
	return &enclaveImpl{backend: &cgoBackend{}}
}

func (b *cgoBackend) available() bool {
	tag := "com.crzy.credctl.probe"
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var keyRef C.SecKeyRef
	errBuf := make([]byte, 256)
	C.lookupKey(cTag, C.int(len(tag)), &keyRef, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if keyRef != 0 {
		C.CFRelease(C.CFTypeRef(keyRef))
	}
	return true
}

func (b *cgoBackend) generateKey(tag string, biometric BiometricPolicy) ([]byte, error) {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	// Map BiometricPolicy to C int: 0=none, 1=any, 2=fingerprint
	var bPolicy C.int
	switch biometric {
	case BiometricAny:
		bPolicy = 1
	case BiometricFingerprint:
		bPolicy = 2
	default:
		bPolicy = 1
	}

	var privateKey C.SecKeyRef
	errBuf := make([]byte, 512)

	rc := C.generateSecureEnclaveKey(cTag, C.int(len(tag)), bPolicy, &privateKey, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("secure enclave key generation failed: %s", cGoString(errBuf))
	}
	defer C.CFRelease(C.CFTypeRef(privateKey))

	return extractRawPublicKey(privateKey)
}

func (b *cgoBackend) lookupKey(tag string) ([]byte, error) {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var keyRef C.SecKeyRef
	errBuf := make([]byte, 512)

	rc := C.lookupKey(cTag, C.int(len(tag)), &keyRef, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("key not found: %s", cGoString(errBuf))
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	return extractRawPublicKey(keyRef)
}

func (b *cgoBackend) deleteKey(tag string) error {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	errBuf := make([]byte, 512)
	rc := C.deleteKey(cTag, C.int(len(tag)), (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return fmt.Errorf("failed to delete key: %s", cGoString(errBuf))
	}
	return nil
}

func (b *cgoBackend) sign(tag string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot sign empty data")
	}

	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var keyRef C.SecKeyRef
	errBuf := make([]byte, 512)

	rc := C.lookupKey(cTag, C.int(len(tag)), &keyRef, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("key not found for signing: %s", cGoString(errBuf))
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	var outSig unsafe.Pointer
	var outSigLen C.int

	rc = C.signData(keyRef, unsafe.Pointer(&data[0]), C.int(len(data)), &outSig, &outSigLen, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("signing failed: %s", cGoString(errBuf))
	}
	defer C.free(outSig)

	return C.GoBytes(outSig, outSigLen), nil
}

// extractRawPublicKey extracts the raw uncompressed EC point bytes from a SecKeyRef.
func extractRawPublicKey(keyRef C.SecKeyRef) ([]byte, error) {
	var outBytes unsafe.Pointer
	var outLen C.int
	errBuf := make([]byte, 512)

	rc := C.extractPublicKeyBytes(keyRef, &outBytes, &outLen, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("failed to extract public key: %s", cGoString(errBuf))
	}
	defer C.free(outBytes)

	return C.GoBytes(outBytes, outLen), nil
}

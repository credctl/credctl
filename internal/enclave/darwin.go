//go:build darwin

package enclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// generateSecureEnclaveKey creates an ECDSA P-256 key pair in the Secure Enclave.
// On success, returns the SecKeyRef for the private key via *outKey and 0.
// On failure, returns non-zero and writes an error description to errBuf.
static int generateSecureEnclaveKey(const char *tag, int tagLen, SecKeyRef *outKey, char *errBuf, int errBufLen) {
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
    CFErrorRef acError = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
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
    memcpy(buf, CFDataGetBytePtr(pubData), len);
    CFRelease(pubData);

    *outBytes = buf;
    *outLen = (int)len;
    return 0;
}

// lookupKey finds an existing key by application tag.
// Returns 0 on success (key found), -1 on failure (not found or error).
static int lookupKey(const char *tag, int tagLen, SecKeyRef *outKey, char *errBuf, int errBufLen) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);

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

// deleteKey deletes a key by application tag.
// Returns 0 on success, -1 on failure.
static int deleteKey(const char *tag, int tagLen, char *errBuf, int errBufLen) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);

    CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tag, tagLen);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);

    OSStatus status = SecItemDelete(query);

    CFRelease(tagData);
    CFRelease(query);

    if (status != errSecSuccess && status != errSecItemNotFound) {
        snprintf(errBuf, errBufLen, "failed to delete key (OSStatus %d)", (int)status);
        return -1;
    }

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
    memcpy(buf, CFDataGetBytePtr(signature), len);
    CFRelease(signature);

    *outSig = buf;
    *outSigLen = (int)len;
    return 0;
}
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
	"unsafe"
)

type darwinEnclave struct{}

func newPlatformEnclave() Enclave {
	return &darwinEnclave{}
}

func (e *darwinEnclave) Available() bool {
	// Try to look up a non-existent key. If the Security framework is accessible,
	// even a "not found" result means the enclave is available.
	tag := "com.crzy.credctl.probe"
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var keyRef C.SecKeyRef
	errBuf := make([]byte, 256)
	// We don't care about the result — just that the call doesn't crash.
	C.lookupKey(cTag, C.int(len(tag)), &keyRef, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if keyRef != 0 {
		C.CFRelease(C.CFTypeRef(keyRef))
	}
	return true
}

func (e *darwinEnclave) GenerateKey(tag string) (*DeviceKey, error) {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var privateKey C.SecKeyRef
	errBuf := make([]byte, 512)

	rc := C.generateSecureEnclaveKey(cTag, C.int(len(tag)), &privateKey, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("secure enclave key generation failed: %s", cGoString(errBuf))
	}
	defer C.CFRelease(C.CFTypeRef(privateKey))

	pubPEM, fingerprint, err := extractPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &DeviceKey{
		Fingerprint: fingerprint,
		PublicKey:   pubPEM,
		Tag:         tag,
		CreatedAt:   time.Now(),
	}, nil
}

func (e *darwinEnclave) LoadKey(tag string) (*DeviceKey, error) {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var keyRef C.SecKeyRef
	errBuf := make([]byte, 512)

	rc := C.lookupKey(cTag, C.int(len(tag)), &keyRef, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("key not found: %s", cGoString(errBuf))
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	pubPEM, fingerprint, err := extractPublicKey(keyRef)
	if err != nil {
		return nil, err
	}

	return &DeviceKey{
		Fingerprint: fingerprint,
		PublicKey:   pubPEM,
		Tag:         tag,
	}, nil
}

func (e *darwinEnclave) DeleteKey(tag string) error {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	errBuf := make([]byte, 512)
	rc := C.deleteKey(cTag, C.int(len(tag)), (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return fmt.Errorf("failed to delete key: %s", cGoString(errBuf))
	}
	return nil
}

func (e *darwinEnclave) Sign(tag string, data []byte) ([]byte, error) {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	// Look up the private key
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

	sig := C.GoBytes(outSig, outSigLen)
	return sig, nil
}

// extractPublicKey extracts the PEM-encoded public key and SHA-256 fingerprint from a SecKeyRef.
func extractPublicKey(keyRef C.SecKeyRef) (pemBytes []byte, fingerprint string, err error) {
	var outBytes unsafe.Pointer
	var outLen C.int
	errBuf := make([]byte, 512)

	rc := C.extractPublicKeyBytes(keyRef, &outBytes, &outLen, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, "", fmt.Errorf("failed to extract public key: %s", cGoString(errBuf))
	}
	defer C.free(outBytes)

	rawBytes := C.GoBytes(outBytes, outLen)

	// rawBytes is the uncompressed EC point: 0x04 || x || y (65 bytes for P-256)
	if len(rawBytes) != 65 || rawBytes[0] != 0x04 {
		return nil, "", fmt.Errorf("unexpected public key format: %d bytes", len(rawBytes))
	}

	x := new(big.Int).SetBytes(rawBytes[1:33])
	y := new(big.Int).SetBytes(rawBytes[33:65])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	hash := sha256.Sum256(derBytes)
	fp := "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])

	return pemBlock, fp, nil
}

// cGoString converts a null-terminated C string in a Go byte slice to a Go string.
func cGoString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

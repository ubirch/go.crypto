package keystore

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC test vectors
var (
	kek = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	key = []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	e1 = []byte{
		0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
		0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
		0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
	}

	e2 = []byte{
		0x96, 0x77, 0x8b, 0x25, 0xae, 0x6c, 0xa4, 0x35,
		0xf9, 0x2b, 0x5b, 0x97, 0xc0, 0x50, 0xae, 0xd2,
		0x46, 0x8a, 0xb8, 0xa1, 0x7a, 0xd8, 0x4e, 0x5d,
	}

	e3 = []byte{
		0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2,
		0x63, 0xe9, 0x77, 0x79, 0x05, 0x81, 0x8a, 0x2a,
		0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7,
	}

	e4 = []byte{
		0x03, 0x1d, 0x33, 0x26, 0x4e, 0x15, 0xd3, 0x32,
		0x68, 0xf2, 0x4e, 0xc2, 0x60, 0x74, 0x3e, 0xdc,
		0xe1, 0xc6, 0xc7, 0xdd, 0xee, 0x72, 0x5a, 0x93,
		0x6b, 0xa8, 0x14, 0x91, 0x5c, 0x67, 0x62, 0xd2,
	}

	e5 = []byte{
		0xa8, 0xf9, 0xbc, 0x16, 0x12, 0xc6, 0x8b, 0x3f,
		0xf6, 0xe6, 0xf4, 0xfb, 0xe3, 0x0e, 0x71, 0xe4,
		0x76, 0x9c, 0x8b, 0x80, 0xa3, 0x2c, 0xb8, 0x95,
		0x8c, 0xd5, 0xd1, 0x7d, 0x6b, 0x25, 0x4d, 0xa1,
	}

	e6 = []byte{
		0x28, 0xc9, 0xf4, 0x04, 0xc4, 0xb8, 0x10, 0xf4,
		0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87, 0xf8, 0x26,
		0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26,
		0xcb, 0xc7, 0xf0, 0xe7, 0x1a, 0x99, 0xf4, 0x3b,
		0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21,
	}

	kek1 = []byte{
		0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1,
		0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e, 0xa1,
		0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
	}

	key1 = []byte{
		0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40,
		0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
		0x50, 0x68, 0xf7, 0x38,
	}

	key2 = []byte{
		0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69,
	}

	ewrap1 = []byte{
		0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc,
		0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22, 0x48, 0xee,
		0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a,
		0x5f, 0x54, 0xf3, 0x73, 0xfa, 0x54, 0x3b, 0x6a,
	}

	ewrap2 = []byte{
		0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41,
		0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b, 0xb2, 0x4f,
	}
)

func aesWrapUnwrapTest(kek []byte, iv []byte, eout []byte, key []byte, keylen uint) bool {
	var otmp, ptmp []byte
	var r int

	otmp = make([]byte, keylen+16)
	ptmp = make([]byte, keylen+16)

	if keylen%8 == 0 {
		r = aesWrapKey(kek, iv, otmp, key, keylen)
	} else {
		r = aesWrapKeyWithpad(kek, otmp, key, keylen)
	}

	if r <= 0 {
		return false
	}

	if eout != nil && !bytes.Equal(eout[:keylen], otmp[:keylen]) {
		return false
	}

	if keylen%8 == 0 {
		r = aesUnwrapKey(kek, iv, ptmp, otmp, uint(r), nil)
	} else {
		r = aesUnwrapKeyWithpad(kek, ptmp, otmp, uint(r))
	}

	if !bytes.Equal(key[:keylen], ptmp[:keylen]) {
		return false
	}

	return true
}

func TestKeystoreRoundtrip(t *testing.T) {
	testKek := []byte("Test kek, len 16")
	testKey := []byte("I am an encrypted key.")

	k := make(Keystore)
	if _, err := k.Get("keyname", testKek); err == nil {
		t.Errorf("Getting a non-existent key should fail")
	}
	if err := k.Set("keyname", testKey, testKek); err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}
	have, err := k.Get("keyname", testKek)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}
	if !bytes.Equal(have, testKey) {
		t.Errorf("Key round trip failed, have %v, want %v", have, testKey)
	}
	delete(k, "keyname")
	if _, err := k.Get("keyname", testKek); err == nil {
		t.Errorf("Getting a deleted key should fail")
	}
}

func TestKeystoreRoundtrip2(t *testing.T) {
	var tests = []struct {
		testName string
		keyname  string
		keyvalue []byte
		kek      []byte
	}{
		{testName: "8ByteKey", keyname: "8ByteKey", keyvalue: []byte("12345678"), kek: []byte("0123456789ABCDEF")},
		{testName: "16ByteKey", keyname: "16ByteKey", keyvalue: []byte("16 Byte long key"), kek: []byte("16 Byte long kek")},
		{testName: "7ByteKey", keyname: "7ByteKey", keyvalue: []byte("1234567"), kek: []byte("0123456789ABCDEF")},
		{testName: "9ByteKey", keyname: "9ByteKey", keyvalue: []byte("123456789"), kek: []byte("0123456789ABCDEF")},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			k := make(Keystore)
			nilKey, err := k.Get(tt.keyname, tt.kek)
			assert.Errorf(t, err, "Getting a non-existent key should fail")
			assert.Nilf(t, nilKey, "Non existing key shold be 'Nil'")

			assert.NoErrorf(t, k.Set(tt.keyname, tt.keyvalue, tt.kek),
				"Failed to set key: %v", err)
			have, err := k.Get(tt.keyname, tt.kek)
			assert.NoErrorf(t, err, "Failed to get key: %v", err)
			assert.NotNilf(t, have, "Existing key should not be 'Nil")
			assert.Equalf(t, have, tt.keyvalue,
				"Key round trip failed, have %v, want %v", have, tt.keyvalue)

			delete(k, tt.keyname)
			deletedKey, err := k.Get(tt.keyname, tt.kek)
			assert.Errorf(t, err, "Getting a deleted key should fail")
			assert.Nilf(t, deletedKey, "Deleted key  shold be 'Nil'")
		})
	}
}

func TestKeystoreRoundtripRandom(t *testing.T) {
	var l uint = 256
	kek := []byte("0123456789ABCDEF")

	randKey := make([]byte, l)
	for i := uint(1); i < l; i++ {
		_, err := rand.Read(randKey)
		require.NoErrorf(t, err, "Random number did not work")
		testName := fmt.Sprintf("%03v Bytes", i)
		t.Run(testName, func(t *testing.T) {
			k := make(Keystore)
			nilKey, err := k.Get("keyname", kek)
			assert.Errorf(t, err, "Getting a non-existent key should fail")
			assert.Nilf(t, nilKey, "Non existing key shold be 'Nil'")

			assert.NoErrorf(t, k.Set("keyname", randKey[:i], kek),
				"Failed to set key: %v", err)
			have, err := k.Get("keyname", kek)
			assert.NoErrorf(t, err, "Failed to get key: %v", err)
			assert.NotNilf(t, have, "Existing key should not be 'Nil")
			assert.Equalf(t, have, randKey[:i],
				"Key round trip failed, have %v, want %v", have, randKey[:i])

			delete(k, "keyname")
			deletedKey, err := k.Get("keyname", kek)
			assert.Errorf(t, err, "Getting a deleted key should fail")
			assert.Nilf(t, deletedKey, "Deleted key  shold be 'Nil'")
		})
	}
}

func TestKeystoreGetError(t *testing.T) {
	getErr := []struct {
		keyname string
		kek     []byte
	}{
		{keyname: "", kek: nil},
		{keyname: "not present", kek: nil},
		{keyname: "present", kek: []byte("this key is not 16 bytes long")},
		{keyname: "present", kek: []byte("012345678901234-")},
	}

	k := make(Keystore)
	if err := k.Set("present", []byte("test"), []byte("0123456789012345")); err != nil {
		t.Fatalf("Failed to set up keystore Get error test case: %v", err)
	}

	for _, tt := range getErr {
		if _, err := k.Get(tt.keyname, tt.kek); err == nil {
			t.Errorf("Expected an error getting %q %q, got none", tt.keyname, string(tt.kek))
		}
	}
}

func TestKeystoreSet(t *testing.T) {
	setErr := []struct {
		keyname  string
		keyvalue []byte
		kek      []byte
	}{
		{keyname: "16ByteKey", keyvalue: []byte("16 Byte long key"), kek: []byte("16 Byte long kek")},
		{keyname: "8ByteKey", keyvalue: []byte("12345678"), kek: []byte("0123456789ABCDEF")},
		{keyname: "7ByteKey", keyvalue: []byte("1234567"), kek: []byte("0123456789ABCDEF")},
		{keyname: "9ByteKey", keyvalue: []byte("123456789"), kek: []byte("0123456789ABCDEF")},
	}

	k := make(Keystore)
	for _, tt := range setErr {
		assert.NoErrorf(t, k.Set(tt.keyname, tt.keyvalue, tt.kek),
			"Expected no error getting %q %q, got one", tt.keyname, string(tt.kek))
	}
}

func TestKeystoreSetError(t *testing.T) {
	setErr := []struct {
		keyname  string
		keyvalue []byte
		kek      []byte
	}{
		{keyname: ""},
		{keyname: "present", keyvalue: nil},
		{keyname: "present", keyvalue: []byte("some key"), kek: []byte("this key is not 16 bytes long")},
	}

	k := make(Keystore)
	for _, tt := range setErr {
		if err := k.Set(tt.keyname, tt.keyvalue, tt.kek); err == nil {
			t.Errorf("Expected an error setting %q %q %q, got none", tt.keyname, string(tt.keyvalue), string(tt.kek))
		}
	}
}

func TestWrapRandom(t *testing.T) {
	sample := make([]byte, 100)
	for i := uint(1); i < 100; i++ {
		_, err := rand.Read(sample)
		require.NoErrorf(t, err, "Random number did not work")
		pass := aesWrapUnwrapTest(kek[:16], nil, nil, sample[:i], i)
		if !pass {
			t.Errorf("Random data of len %d failed wrap unwrap test", i)
		} else {
			t.Logf("Random data of len %d passed wrap unwrap test", i)
		}
	}
}

func TestLargeKey(t *testing.T) {
	kek := make([]byte, 16)
	key := make([]byte, 8192)
	for i := 128; i <= len(key); i *= 2 {
		_, err := rand.Read(key)
		require.NoErrorf(t, err, "Random number did not work")
		pass := aesWrapUnwrapTest(kek, nil, nil, key[:i], uint(i))
		if !pass {
			t.Errorf("Random key data of len %d failed wrap unwrap test", i)
		} else {
			t.Logf("Random key data of len %d passed wrap unwrap test", i)
		}
	}
}

func TestWrapRFCTestVectors(t *testing.T) {
	cases := []struct {
		kek    []byte
		eout   []byte
		key    []byte
		keylen uint
	}{
		{kek[:16], e1, key, 16},
		{kek[:24], e2, key, 16},
		{kek, e3, key, 16},
		{kek[:24], e4, key, 24},
		{kek, e5, key, 24},
		{kek, e6, key, 32},
		{kek1, ewrap1, key1, 20},
		{kek1, ewrap2, key2, 7},
	}

	for i, tt := range cases {
		pass := aesWrapUnwrapTest(tt.kek, nil, tt.eout, tt.key, tt.keylen)
		if !pass {
			t.Errorf("Case %d failed wrap unwrap test: %#v\n", i, tt)
		} else {
			t.Logf("Case %d passed wrap unwrap test: %#v\n", i, tt)
		}
	}
}

func BenchmarkKeystore(b *testing.B) {
	for i := 0; i < b.N; i++ {
		aesWrapUnwrapTest(kek[:16], nil, e1, key, 16)
	}
}

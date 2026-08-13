package proxy

import (
	"crypto/aes"
	"encoding/base64"
	"strings"

	"github.com/huabanmao168/SubPanel/internal/parser"
)

func isLumiUA(ua string) bool {
	return strings.Contains(strings.ToLower(ua), "lumi")
}

func tokenFromSubscribePath(pr *parser.Request) string {
	if pr == nil || pr.Tenant == nil || pr.Path == "" {
		return ""
	}
	base := strings.TrimRight(pr.Tenant.SubscribePath, "/")
	path := strings.TrimRight(pr.Path, "/")
	if base == "" || path == "" || path == base || !strings.HasPrefix(path, base+"/") {
		return ""
	}
	rest := strings.Trim(strings.TrimPrefix(path, base), "/")
	if rest == "" {
		return ""
	}
	parts := strings.Split(rest, "/")
	return parts[len(parts)-1]
}

func lumiKeyMaterial(pr *parser.Request) (string, bool) {
	if pr == nil || pr.Token == "" || len([]byte(pr.Token)) < 16 {
		return "", false
	}
	return pr.Token, true
}

func lumiAES128Key(material string) ([]byte, bool) {
	b := []byte(material)
	if len(b) < 16 {
		return nil, false
	}
	key := make([]byte, 0, 16)
	key = append(key, b[:8]...)
	key = append(key, b[len(b)-8:]...)
	return key, true
}

func encryptLumiSubscription(pr *parser.Request, plaintext []byte) ([]byte, bool) {
	material, ok := lumiKeyMaterial(pr)
	if !ok || len(plaintext) == 0 {
		return plaintext, false
	}
	// AES-128-ECB:直接取订阅 token 前 8 字节 + 后 8 字节作为 16 字节 key。
	key, ok := lumiAES128Key(material)
	if !ok {
		return plaintext, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return plaintext, false
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	for off := 0; off < len(padded); off += block.BlockSize() {
		block.Encrypt(ciphertext[off:off+block.BlockSize()], padded[off:off+block.BlockSize()])
	}
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), true
}

func decryptLumiSubscriptionForTest(pr *parser.Request, body []byte) ([]byte, bool) {
	material, ok := lumiKeyMaterial(pr)
	if !ok {
		return nil, false
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, false
	}
	key, ok := lumiAES128Key(material)
	if !ok {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil || len(payload) == 0 || len(payload)%block.BlockSize() != 0 {
		return nil, false
	}
	plainPadded := make([]byte, len(payload))
	for off := 0; off < len(payload); off += block.BlockSize() {
		block.Decrypt(plainPadded[off:off+block.BlockSize()], payload[off:off+block.BlockSize()])
	}
	plain, ok := pkcs7Unpad(plainPadded, block.BlockSize())
	if !ok {
		return nil, false
	}
	return plain, true
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, bool) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, false
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > blockSize || pad > len(b) {
		return nil, false
	}
	for _, v := range b[len(b)-pad:] {
		if int(v) != pad {
			return nil, false
		}
	}
	return b[:len(b)-pad], true
}

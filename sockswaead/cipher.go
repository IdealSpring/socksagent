package sockswaead

import (
	"crypto/cipher"
	"crypto/sha1"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type KeySizeError int
func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

type Cipher interface {
	KeySize() int
	SaltSize() int
	Encrypter(salt []byte) (cipher.AEAD, error)		// 加密
	Decrypter(salt []byte) (cipher.AEAD, error)		// 解密
}

type metaCipher struct {
	psk []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}
func (m *metaCipher) KeySize() int { return len(m.psk) }
func (m *metaCipher) SaltSize() int {
	if ks := m.KeySize(); ks > 16 {
		return ks
	}
	return 16
}
func (m *metaCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, m.KeySize())
	hkdfSHA1(m.psk, salt, []byte("ss-subkey"), subkey)
	return m.makeAEAD(subkey)
}
func (m *metaCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, m.KeySize())
	hkdfSHA1(m.psk, salt, []byte("ss-subkey"), subkey)
	return m.makeAEAD(subkey)
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}

// Chacha20Poly1305使用预共享密钥创建新密码。长度（psk）必须是32。
func Chacha20Poly1305(psk []byte)(Cipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, KeySizeError(chacha20poly1305.KeySize)
	}
	return &metaCipher{psk: psk, makeAEAD:chacha20poly1305.New}, nil
}

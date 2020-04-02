package core

import (
	"ccut.cn/socksagent/sockswaead"
	"crypto/md5"
	"errors"
	"net"
	"strings"
)

type StreamConnCipher interface {
	StreamConn(net.Conn) net.Conn
}

type PacketConnCipher interface {
	PacketConn(net.PacketConn) net.PacketConn
}

type Cipher interface {
	StreamConnCipher
	PacketConnCipher
}

var CipherNotSupportedError = errors.New("cipher not supported error")

// 加密算法
const (
	aeadChacha20Poly1305 = "AEAD_CHACHA20_POLY1305"
)

// 加密算法列表
var aeadList = map[string]struct {
	KeySize int
	New func([]byte) (sockswaead.Cipher, error)
} {
	aeadChacha20Poly1305:{32, sockswaead.Chacha20Poly1305},
}


type dummy struct{}
func (dummy) StreamConn(c net.Conn) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

type aeadCipher struct {
	sockswaead.Cipher
}
func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn {
	return sockswaead.NewConn(c, aead)
}
func (aead *aeadCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return sockswaead.NewPacketConn(c, aead)
}

func PickCipher(name string, key []byte, password string) (Cipher, error) {
	name = strings.ToUpper(name)

	// 选择加密算法
	switch name {
	case "DUMMY":
		return &dummy{}, nil
	case "AEAD_CHACHA20_POLY1305":
		name = aeadChacha20Poly1305
	}

	if choice, ok := aeadList[name]; ok {
		// key 不存在，从密码派生
		if len(key) == 0 {
			key = kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, sockswaead.KeySizeError(choice.KeySize)
		}

		aead, err := choice.New(key)
		return &aeadCipher{aead}, err
	}

	return nil, CipherNotSupportedError
}

// 派生密钥
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

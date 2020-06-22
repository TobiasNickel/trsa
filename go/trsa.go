package trsa

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

// Keypair holds the public and the private rsa key
type Keypair struct {
	Public  []byte
	Private []byte
}

// GenerateKeypair generate a keyPair and return a Keypair
func GenerateKeypair(bitLength int) (*Keypair, error) {
	public, private, err := GenerateKeys(bitLength)
	if err != nil {
		return nil, err
	}
	return NewKeypair(public, private)
}

// GenerateKeys return public (first) and private(second) key as pem,
func GenerateKeys(bitLength int) ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bitLength)
	if err != nil {
		return nil, nil, err
	}

	privBlock := pem.Block{}
	privBlock.Type = "RSA PRIVATE KEY"
	privBlock.Bytes = x509.MarshalPKCS1PrivateKey(privKey)

	var privateKeyBuffer bytes.Buffer
	privateKeyBufferWriter := bufio.NewWriter(&privateKeyBuffer)
	err = pem.Encode(privateKeyBufferWriter, &privBlock)
	if err != nil {
		return nil, nil, err
	}
	privateKey := make([]byte, privateKeyBufferWriter.Buffered())
	privateKeyBufferWriter.Flush()
	privateKeyBuffer.Read(privateKey)

	pubKey := privKey.Public()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}

	pubBlock := pem.Block{}
	pubBlock.Type = "PUBLIC KEY"
	pubBlock.Bytes = publicKeyBytes
	var publicKeyBuffer bytes.Buffer
	publicKeyBufferWriter := bufio.NewWriter(&publicKeyBuffer)
	err = pem.Encode(publicKeyBufferWriter, &pubBlock)
	if err != nil {
		return nil, nil, err
	}
	publicKey := make([]byte, publicKeyBufferWriter.Buffered())
	publicKeyBufferWriter.Flush()
	publicKeyBuffer.Read(publicKey)

	return publicKey, privateKey, nil
}

// NewKeypair creates a keypair, each key is optional,
// but the methods needing the missing keys will fail.
// This is useful when you only have the public key, and need to encrypt or verify
func NewKeypair(publicKey []byte, privateKey []byte) (*Keypair, error) {
	return &Keypair{
		Public:  publicKey,
		Private: privateKey,
	}, nil
}

func parsePublicKey(publicKeyPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		return nil, errors.New("could not decode public key pem")
	}
	p, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := p.(*rsa.PublicKey)
	if ok != true {
		return nil, errors.New("public key has the wrong type")
	}
	return publicKey, nil
}
func parsePrivateKey(privateKeyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("could not decode private key pem")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Encrypt quick method to encrypt using the public key
func (key *Keypair) Encrypt(data []byte) ([]byte, error) {
	return Encrypt(data, key.Public)
}

// Encrypt using the public key without creating a keypair
func Encrypt(data []byte, publicKeyPem []byte) ([]byte, error) {
	publicKey, err := parsePublicKey(publicKeyPem)
	if err != nil {
		return nil, err
	}
	// 11 is part of the rsa chunk, 32 the length of a sha1 hash
	partLen := publicKey.N.BitLen()/8 - 11 - 32
	chunks := split(data, partLen)

	buffer := bytes.NewBuffer([]byte{})
	for _, chunk := range chunks {
		bts, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, chunk, nil)
		if err != nil {
			return nil, err
		}
		buffer.Write(bts)
	}

	return buffer.Bytes(), nil
}

// Decrypt using the keypairs privateKey
func (key *Keypair) Decrypt(encrypted []byte) ([]byte, error) {
	return Decrypt(encrypted, key.Private)
}

// Decrypt using a privatekey without creating a keypair
func Decrypt(encrypted []byte, privateKeyPem []byte) ([]byte, error) {
	privateKey, err := parsePrivateKey(privateKeyPem)
	if err != nil {
		return nil, err
	}
	partLen := privateKey.N.BitLen() / 8
	chunks := split(encrypted, partLen)

	buffer := bytes.NewBuffer([]byte{})
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, chunk, nil)
		if err != nil {
			return nil, err
		}
		buffer.Write(decrypted)
	}

	return buffer.Bytes(), nil
}

// Sign data
func (key *Keypair) Sign(data []byte) ([]byte, error) {
	return Sign(data, key.Private)
}

// Sign data
func Sign(data []byte, privateKeyPem []byte) ([]byte, error) {
	privateKey, err := parsePrivateKey(privateKeyPem)
	if err != nil {
		return nil, err
	}
	h := crypto.SHA256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(sign)), err
}

// Verify data's signature
func (key *Keypair) Verify(data []byte, signature []byte) error {
	return Verify(data, signature, key.Public)
}

// Verify data's signature
func Verify(data []byte, signature []byte, publicKeyPem []byte) error {
	publicKey, err := parsePublicKey(publicKeyPem)
	if err != nil {
		return err
	}
	h := crypto.SHA256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := hex.DecodeString(string(signature))
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, decodedSign)
}

// https://gist.github.com/xlab/6e204ef96b4433a697b3
func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

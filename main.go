package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

var EncryptionTypes = map[string]uint32{
	//"SHA2":     1,
	"Rijndael": 2,
	"AES":      2,
	"ArcFour":  4,
	"TwoFish":  8,
}

type Metadata struct {
	signature1 uint32
	signature2 uint32
	flags      uint32
	version    uint32
	seed       [16]byte
	iv         [16]byte
	groups     uint32
	entries    uint32
	hash       [32]byte
	seed2      [32]byte
	rounds     uint32
}

type KeepassXDatabase struct {
	*Metadata
	password string
	keyfile  string
	payload  []byte
}

func NewKeepassXDatabase(password, keyfile string) (*KeepassXDatabase, error) {
	return &KeepassXDatabase{
		Metadata: new(Metadata),
		password: password,
		keyfile:  keyfile,
	}, nil
}

func (m *Metadata) ReadFrom(r io.Reader) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	n, err := io.ReadFull(r, uint32Bytes)
	n64 := int64(n)
	m.signature1 = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	m.signature2 = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	m.flags = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	m.version = binary.LittleEndian.Uint32(uint32Bytes)

	var seed [16]byte
	n, err = io.ReadFull(r, seed[:])
	n64 += int64(n)
	m.seed = seed

	var encryption [16]byte
	n, err = io.ReadFull(r, encryption[:])
	n64 += int64(n)
	m.iv = encryption

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	m.groups = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	m.entries = binary.LittleEndian.Uint32(uint32Bytes)

	var hash [32]byte
	n, err = io.ReadFull(r, hash[:])
	n64 += int64(n)
	m.hash = hash

	var seed2 [32]byte
	n, err = io.ReadFull(r, seed2[:])
	n64 += int64(n)
	m.seed2 = seed2

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	m.rounds = binary.LittleEndian.Uint32(uint32Bytes)

	return n64, err
}

func getEncryptionFlag(flag uint32) string {
	for k, v := range EncryptionTypes {
		if v&flag != 0 {
			return k
		}
	}
	return ""
}

func (k *KeepassXDatabase) decryptPayload(content []byte, key []byte,
	encryption_type string, iv [16]byte) ([]byte, error) {
	var err error
	var data []byte
	if encryption_type != "Rijndael" {
		return data, errors.New(fmt.Sprintf("Unsupported encryption type: %s", encryption_type))
	}
	decryptor, err := aes.NewCipher(key)
	if err != nil {
		return data, err
	}
	mode := cipher.NewCBCDecrypter(decryptor, iv[:])
	mode.CryptBlocks(content, data)
	return data, err
}

func (k *KeepassXDatabase) calculateKey() ([]byte, error) {
	// TODO: support keyfile
	hash := sha256.New()
	hash.Write([]byte(k.password))
	key := hash.Sum(nil)
	cipher, err := aes.NewCipher(k.seed2[:])
	if err != nil {
		return key, err
	}
	for i := 0; i < int(k.rounds); i++ {
		cipher.Encrypt(key, key)
	}
	hash.Reset()
	hash.Write(key)
	return hash.Sum(nil), nil
}

func (k *KeepassXDatabase) parsePayload(payload []byte) error {
	return nil
}

func (k *KeepassXDatabase) ReadFrom(r io.Reader) (int64, error) {
	n, err := k.Metadata.ReadFrom(r)
	if err != nil {
		return n, err
	}
	var content []byte
	_, err = io.ReadFull(r, content[:])
	encryption_type := getEncryptionFlag(k.flags)
	key, err := k.calculateKey()
	if err != nil {
		return n, err
	}
	payload, err := k.decryptPayload(content, key, encryption_type, k.iv)
	err = k.parsePayload(payload)
	return n, err
}

func main() {
	path := os.Args[1]
	var password, keyfile string
	if len(os.Args) > 2 {
		password = os.Args[2]
	}
	if len(os.Args) > 3 {
		keyfile = os.Args[3]
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer f.Close()
	db, err := NewKeepassXDatabase(password, keyfile)
	if err != nil {
		log.Fatalf("%v", err)
	}
	_, err = db.ReadFrom(f)
	if err != nil {
		log.Fatalf("%v", err)
	}
}

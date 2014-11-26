package main

import (
	"encoding/binary"
	"io"
	"log"
	"os"
)

var EncryptionTypes = map[string]int{
	"SHA2":     1,
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
	encryption [16]byte
	groups     uint32
	entries    uint32
	hash       [32]byte
	seed2      [32]byte
	rounds     uint32
}

type KeepassXDatabase struct {
	*Metadata
	payload []byte
}

func NewKeepassXDatabase() (*KeepassXDatabase, error) {
	return &KeepassXDatabase{
		Metadata: new(Metadata),
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
	m.encryption = encryption

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

func (k *KeepassXDatabase) decryptPayload(content []byte, seed [16]byte, seed2 [32]byte, rounds uint32, flags uint32, encryption [16]byte) ([]byte, error) {
	var err error
	var data []byte
	return data, err
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
	payload, err := k.decryptPayload(content, k.seed, k.seed2, k.rounds, k.flags, k.encryption)
	err = k.parsePayload(payload)
	return n, err
}

func main() {
	path := os.Args[1]
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer f.Close()
	db, err := NewKeepassXDatabase()
	if err != nil {
		log.Fatalf("%v", err)
	}
	_, err = db.ReadFrom(f)
	if err != nil {
		log.Fatalf("%v", err)
	}
}

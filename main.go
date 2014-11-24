package main

import (
	"encoding/binary"
	"io"
	"log"
	"os"
)

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
}

func NewKeepassXDatabase() (*KeepassXDatabase, error) {
	return &KeepassXDatabase{
		Metadata: new(Metadata),
	}, nil
}

func (k *KeepassXDatabase) ReadFrom(r io.Reader) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	n, err := io.ReadFull(r, uint32Bytes)
	n64 := int64(n)
	k.signature1 = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	k.signature2 = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	k.flags = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	k.version = binary.LittleEndian.Uint32(uint32Bytes)

	var seed [16]byte
	n, err = io.ReadFull(r, seed[:])
	n64 += int64(n)
	k.seed = seed

	var encryption [16]byte
	n, err = io.ReadFull(r, encryption[:])
	n64 += int64(n)
	k.encryption = encryption

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	k.groups = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	k.entries = binary.LittleEndian.Uint32(uint32Bytes)

	var hash [32]byte
	n, err = io.ReadFull(r, hash[:])
	n64 += int64(n)
	k.hash = hash

	var seed2 [32]byte
	n, err = io.ReadFull(r, seed2[:])
	n64 += int64(n)
	k.seed2 = seed2

	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	k.rounds = binary.LittleEndian.Uint32(uint32Bytes)

	return n64, err
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

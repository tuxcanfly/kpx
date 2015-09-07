package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

// SYS_USR_ID is a reserved  entry id
// It is used to skip processing system entries
const SYS_USR_ID = uint32(0)

// Sha256 returns sha256 hash of the given data
func Sha256(k []byte) []byte {
	hash := sha256.New()
	hash.Write(k)
	return hash.Sum(nil)
}

// ErrInvalidEncryptionFlag is returned on an invalid encryption flag
var ErrInvalidEncryptionFlag error

var EncryptionTypes = map[string]uint32{
	// TODO: Support these
	//"SHA2":     1,
	//"AES":      2,
	"Rijndael": 2,
	"ArcFour":  4,
	"TwoFish":  8,
}

// ParseError is raised when there is an error during parsing of the payload
var ParseError = errors.New("unable to parse payload")

type BaseType struct{}

func (b BaseType) Decode(payload []byte) interface{} {
	return payload
}

type StringType struct{}

func (s StringType) Decode(payload []byte) string {
	return strings.TrimRight(string(payload[:]), "\x00")
}

type IntegerType struct{}

func (i IntegerType) Decode(payload []byte) uint32 {
	return binary.LittleEndian.Uint32(payload)
}

type ShortType struct{}

func (s ShortType) Decode(payload []byte) uint16 {
	return binary.LittleEndian.Uint16(payload)
}

type UUIDType struct{}

func (u UUIDType) Decode(payload []byte) interface{} {
	return strings.TrimRight(string(payload[:]), "\x00")
}

type DateType struct{}

func (d DateType) Decode(payload []byte) interface{} {
	year := int((uint16(payload[0]) << 6) | (uint16(payload[1]) >> 2))
	month := int(((payload[1] & 0x00000003) << 2) | (payload[2] >> 6))
	day := int((payload[2] >> 1) & 0x0000001F)
	hour := int(((payload[2] & 0x00000001) << 4) | (payload[3] >> 4))
	minutes := int(((payload[3] & 0x0000000F) << 2) | (payload[4] >> 6))
	seconds := int(payload[4] & 0x0000003F)
	return time.Date(year, time.Month(month), day, hour, minutes, seconds, 0, time.UTC)
}

// Group represents a KeepassX entries group.
type Group struct {
	ignored bool
	id      uint32
	name    string
	imageid uint32
	level   uint16
	flags   uint32
}

// Entry represents a KeepassX entry.
type Entry struct {
	ignored         bool
	id              uint32
	groupid         uint32
	imageid         uint32
	title           string
	url             string
	username        string
	password        string
	notes           string
	creation_time   time.Time
	last_mod_time   time.Time
	last_acc_time   time.Time
	expiration_time time.Time
	binary_desc     string
	binary_data     []byte
	group           *Group
}

// Metadata is the metadata stored in the KeepassX database.
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

// KeepassXDatabase is the KeepassX database.
type KeepassXDatabase struct {
	*Metadata
	password []byte
	keyfile  string
	payload  []byte
	groupIdx map[uint32]*Group
	results  map[uint32][]Entry
}

// NewKeepassXDatabase returns an instance of KeepassXDatabase from the given
// password and keyfile
func NewKeepassXDatabase(password []byte, keyfile string) (*KeepassXDatabase, error) {
	return &KeepassXDatabase{
		Metadata: new(Metadata),
		password: password,
		keyfile:  keyfile,
		groupIdx: make(map[uint32]*Group),
	}, nil
}

// ReadFrom reads the given reader and loads the metadata into memory.
func (m *Metadata) ReadFrom(r io.Reader) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	n, err := io.ReadFull(r, uint32Bytes)
	if err != nil {
		return 0, err
	}
	n64 := int64(n)
	m.signature1 = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.signature2 = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.flags = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.version = binary.LittleEndian.Uint32(uint32Bytes)

	var seed [16]byte
	n, err = io.ReadFull(r, seed[:])
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.seed = seed

	var encryption [16]byte
	n, err = io.ReadFull(r, encryption[:])
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.iv = encryption

	n, err = io.ReadFull(r, uint32Bytes)
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.groups = binary.LittleEndian.Uint32(uint32Bytes)

	n, err = io.ReadFull(r, uint32Bytes)
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.entries = binary.LittleEndian.Uint32(uint32Bytes)

	var hash [32]byte
	n, err = io.ReadFull(r, hash[:])
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.hash = hash

	var seed2 [32]byte
	n, err = io.ReadFull(r, seed2[:])
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.seed2 = seed2

	n, err = io.ReadFull(r, uint32Bytes)
	if err != nil {
		return 0, err
	}
	n64 += int64(n)
	m.rounds = binary.LittleEndian.Uint32(uint32Bytes)

	return n64, nil
}

func getEncryptionFlag(flag uint32) (string, error) {
	for k, v := range EncryptionTypes {
		if v&flag != 0 {
			return k, nil
		}
	}
	return "", ErrInvalidEncryptionFlag
}

func (k *KeepassXDatabase) decryptPayload(content []byte, key []byte,
	encryption_type string, iv [16]byte) ([]byte, error) {
	data := make([]byte, len(content))
	if encryption_type != "Rijndael" {
		// Only Rijndael is supported atm.
		return data, errors.New(fmt.Sprintf("Unsupported encryption type: %s",
			encryption_type))
	}
	decryptor, err := aes.NewCipher(key)
	if err != nil {
		return data, err
	}
	mode := cipher.NewCBCDecrypter(decryptor, iv[:])
	mode.CryptBlocks(data, content)
	return data, err
}

// calculateKey calculates the key required to decrypt the payload.
func (k *KeepassXDatabase) calculateKey() ([]byte, error) {
	// TODO: support keyfile
	key := Sha256(k.password)
	cipher, err := aes.NewCipher(k.seed2[:])
	if err != nil {
		return key, err
	}
	for i := 0; i < int(k.rounds); i++ {
		cipher.Encrypt(key[:16], key[:16])
		cipher.Encrypt(key[16:], key[16:])
	}
	key = Sha256(key)
	return Sha256(append(k.seed[:], key...)), nil
}

func (k *KeepassXDatabase) parsePayload(payload []byte) (map[uint32][]Entry, error) {
	groups, offset, err := k.parseGroups(payload)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(groups); i++ {
		k.groupIdx[groups[i].id] = &groups[i]
	}
	entries, err := k.parseEntries(payload[offset:])
	if err != nil {
		return nil, err
	}
	results := make(map[uint32][]Entry)
	for _, entry := range entries {
		results[entry.groupid] = append(results[entry.groupid], entry)
	}
	return results, nil
}

func (k *KeepassXDatabase) getGroup(id uint32) (*Group, error) {
	g, ok := k.groupIdx[id]
	if ok {
		return g, nil
	}
	return nil, errors.New("group not found")
}

func (k *KeepassXDatabase) parseEntries(payload []byte) ([]Entry, error) {
	offset := 0
	var entries []Entry
	for i := 0; i < int(k.entries); i++ {
		var e Entry
	out:
		for {
			field_type := binary.LittleEndian.Uint16(payload[offset : offset+2])
			offset += 2
			field_size := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
			offset += 4
			switch field_type {
			case 0x1:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.id = s.Decode(data)
			case 0x2:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.groupid = s.Decode(data)
				group, err := k.getGroup(e.groupid)
				if err != nil {
					group = nil
				}
				e.group = group
			case 0x3:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.imageid = s.Decode(data)
			case 0x4:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.title = s.Decode(data)
			case 0x5:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.url = s.Decode(data)
			case 0x6:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.username = s.Decode(data)
			case 0x7:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.password = s.Decode(data)
			case 0x8:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.notes = s.Decode(data)
			case 0x9:
				d := DateType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i := d.Decode(data)
				e.creation_time = i.(time.Time)
			case 0xa:
				d := DateType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i := d.Decode(data)
				e.last_mod_time = i.(time.Time)
			case 0xb:
				d := DateType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i := d.Decode(data)
				e.last_acc_time = i.(time.Time)
			case 0xc:
				d := DateType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i := d.Decode(data)
				e.expiration_time = i.(time.Time)
			case 0xd:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				e.binary_desc = s.Decode(data)
			case 0xe:
				b := BaseType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i := b.Decode(data)
				e.binary_data = i.([]byte)
			case 0xffff:
				break out
			}
		}
		if e.id != SYS_USR_ID {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

func (k *KeepassXDatabase) parseGroups(payload []byte) ([]Group, int, error) {
	offset := 0
	var groups []Group
	for i := 0; i < int(k.groups); i++ {
		var g Group
	out:
		for {
			if offset+2 > len(payload) {
				return nil, 0, ParseError
			}
			field_type := binary.LittleEndian.Uint16(payload[offset : offset+2])
			offset += 2
			field_size := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
			offset += 4
			switch field_type {
			case 0x1:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				g.id = s.Decode(data)
			case 0x2:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				g.name = s.Decode(data)
			case 0x7:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				g.imageid = s.Decode(data)
			case 0x8:
				s := ShortType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				g.level = s.Decode(data)
			case 0x9:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				g.flags = s.Decode(data)
			case 0xffff:
				break out
			}
		}
		groups = append(groups, g)
	}
	return groups, offset, nil
}

// ReadFrom reads the given reader and loads the keepassx database file into
// memory.
func (k *KeepassXDatabase) ReadFrom(r io.Reader) (int64, error) {
	n, err := k.Metadata.ReadFrom(r)
	if err != nil {
		return n, err
	}
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return n, err
	}
	encryption_type, err := getEncryptionFlag(k.flags)
	if err != nil {
		return n, err
	}
	key, err := k.calculateKey()
	if err != nil {
		return n, err
	}
	payload, err := k.decryptPayload(content, key, encryption_type, k.iv)
	if err != nil {
		return n, err
	}
	results, err := k.parsePayload(payload)
	if err != nil {
		return n, err
	}
	k.results = results
	return n, err
}

func main() {
	var path string
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if path == "" || path == "-h" || path == "--help" {
		log.Printf("Usage: kpx <path/to/keepass.kdb>")
		return
	}
	if !strings.HasSuffix(path, ".kdb") {
		log.Fatalf("unknown file format")
	}
	var keyfile string
	if len(os.Args) > 2 {
		keyfile = os.Args[2]
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	defer f.Close()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Handle interrupts when reading password
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	fmt.Print("Password: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Print("\n")
	db, err := NewKeepassXDatabase(password, keyfile)
	if err != nil {
		log.Fatalf("%v", err)
	}
	_, err = db.ReadFrom(f)
	if err != nil {
		log.Fatalf("%v", err)
	}
	// Write the results to  stdout
	for id, entries := range db.results {
		group, err := db.getGroup(id)
		if err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("===== %v ======\n", group.name)
		for i, entry := range entries {
			fmt.Printf("%v |  %v | %v |  %v\n", entry.id, i, entry.title, entry.url)
		}
		fmt.Printf("===== x ======\n")
	}
}

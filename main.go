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

// SystemUserID is a reserved id used for processing system entries
const SystemUserID = uint32(0)

// Sha256 returns sha256 hash of the given data
func Sha256(k []byte) []byte {
	hash := sha256.New()
	hash.Write(k)
	return hash.Sum(nil)
}

// ErrInvalidEncryptionFlag is returned on an invalid encryption flag
var ErrInvalidEncryptionFlag error

// EncryptionTypes maps supported encryption types and the flags
var EncryptionTypes = map[string]uint32{
	// TODO: Support these
	//"SHA2":     1,
	//"AES":      2,
	"Rijndael": 2,
	"ArcFour":  4,
	"TwoFish":  8,
}

// ErrParseFailed is returned when parsing payload fails
var ErrParseFailed = errors.New("unable to parse payload")

func parseBinary(payload []byte) []byte {
	return payload
}

func parseString(payload []byte) string {
	return strings.TrimRight(string(payload[:]), "\x00")
}

func parseInt(payload []byte) uint32 {
	return binary.LittleEndian.Uint32(payload)
}

func parseSmallInt(payload []byte) uint16 {
	return binary.LittleEndian.Uint16(payload)
}

func parseUUID(payload []byte) interface{} {
	return strings.TrimRight(string(payload[:]), "\x00")
}

func parseTime(payload []byte) time.Time {
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
	id       uint32
	groupid  uint32
	group    *Group
	imageid  uint32
	title    string
	url      string
	username string
	password string
	ignored  bool
	notes    string
	created  time.Time
	modified time.Time
	accessed time.Time
	expiry   time.Time
	binDesc  string
	binData  []byte
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
// password and keyfile.
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

// EncryptionFlag returns the encryption type flag.
func EncryptionFlag(flag uint32) (string, error) {
	for k, v := range EncryptionTypes {
		if v&flag != 0 {
			return k, nil
		}
	}
	// invalid flag
	return "", ErrInvalidEncryptionFlag
}

// decryptPayload decrypts the given payload.
func (k *KeepassXDatabase) decryptPayload(content []byte, key []byte,
	encryptionType string, iv [16]byte) ([]byte, error) {
	data := make([]byte, len(content))
	if encryptionType != "Rijndael" {
		// Only Rijndael is supported atm.
		return data, fmt.Errorf("Unsupported encryption type: %s", encryptionType)
	}
	decryptor, err := aes.NewCipher(key)
	if err != nil {
		return data, err
	}
	// Block mode CBC
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
	// divide key into half and encrypt with cipher
	for i := 0; i < int(k.rounds); i++ {
		cipher.Encrypt(key[:16], key[:16])
		cipher.Encrypt(key[16:], key[16:])
	}
	key = Sha256(key)
	return Sha256(append(k.seed[:], key...)), nil
}

// parsePayload parses the payload and returns the results as a map.
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

// getGroup returns the group for the given group id.
func (k *KeepassXDatabase) getGroup(id uint32) (*Group, error) {
	g, ok := k.groupIdx[id]
	if ok {
		return g, nil
	}
	return nil, errors.New("group not found")
}

// parseEntries parses the payload and returns an array of entries.
func (k *KeepassXDatabase) parseEntries(payload []byte) ([]Entry, error) {
	offset := 0
	var entries []Entry
	for i := 0; i < int(k.entries); i++ {
		var e Entry
	out:
		for {
			fieldType := binary.LittleEndian.Uint16(payload[offset : offset+2])
			offset += 2
			fieldSize := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
			offset += 4
			switch fieldType {
			case 0x1:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.id = parseInt(data)
			case 0x2:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.groupid = parseInt(data)
				group, err := k.getGroup(e.groupid)
				if err != nil {
					group = nil
				}
				e.group = group
			case 0x3:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.imageid = parseInt(data)
			case 0x4:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.title = parseString(data)
			case 0x5:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.url = parseString(data)
			case 0x6:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.username = parseString(data)
			case 0x7:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.password = parseString(data)
			case 0x8:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.notes = parseString(data)
			case 0x9:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.created = parseTime(data)
			case 0xa:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.modified = parseTime(data)
			case 0xb:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.accessed = parseTime(data)
			case 0xc:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.expiry = parseTime(data)
			case 0xd:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.binDesc = parseString(data)
			case 0xe:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				e.binData = parseBinary(data)
			case 0xffff:
				break out
			}
		}
		// SystemUserID is reserved for system entries
		if e.id != SystemUserID {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// parseGroups parses the given payload and returns an array of groups.
func (k *KeepassXDatabase) parseGroups(payload []byte) ([]Group, int, error) {
	offset := 0
	var groups []Group
	for i := 0; i < int(k.groups); i++ {
		var g Group
	out:
		for {
			// Must be able to read the next two bytes
			if offset+2 > len(payload) {
				return nil, 0, ErrParseFailed
			}
			fieldType := binary.LittleEndian.Uint16(payload[offset : offset+2])
			offset += 2
			fieldSize := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
			offset += 4
			switch fieldType {
			case 0x1:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				g.id = parseInt(data)
			case 0x2:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				g.name = parseString(data)
			case 0x7:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				g.imageid = parseInt(data)
			case 0x8:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				g.level = parseSmallInt(data)
			case 0x9:
				data := payload[offset : offset+fieldSize]
				offset += fieldSize
				g.flags = parseInt(data)
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
	encryptionType, err := EncryptionFlag(k.flags)
	if err != nil {
		return n, err
	}
	key, err := k.calculateKey()
	if err != nil {
		return n, err
	}
	payload, err := k.decryptPayload(content, key, encryptionType, k.iv)
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
	// Print help
	if path == "" || path == "-h" || path == "--help" {
		log.Printf("Usage: kpx <path/to/keepass.kdb>")
		return
	}
	if !strings.HasSuffix(path, ".kdb") {
		log.Fatal("unknown file format")
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

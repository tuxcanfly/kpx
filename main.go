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
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
)

const SYS_USR_ID = uint32(0)

func Sha256(k []byte) []byte {
	hash := sha256.New()
	hash.Write(k)
	return hash.Sum(nil)
}

var EncryptionTypes = map[string]uint32{
	// TODO: Support these
	//"SHA2":     1,
	//"AES":      2,
	"Rijndael": 2,
	"ArcFour":  4,
	"TwoFish":  8,
}

type Grouper interface {
	Decode(payload []byte) (interface{}, error)
}

type BaseType struct{}

func (b BaseType) Decode(payload []byte) (interface{}, error) {
	return payload, nil
}

type StringType struct{}

func (s StringType) Decode(payload []byte) (interface{}, error) {
	return strings.TrimRight(string(payload[:]), "\x00"), nil
}

type IntegerType struct{}

func (i IntegerType) Decode(payload []byte) (interface{}, error) {
	return binary.LittleEndian.Uint32(payload), nil
}

type ShortType struct{}

func (s ShortType) Decode(payload []byte) (interface{}, error) {
	return binary.LittleEndian.Uint16(payload), nil
}

type UUIDType struct{}

func (u UUIDType) Decode(payload []byte) (interface{}, error) {
	return strings.TrimRight(string(payload[:]), "\x00"), nil
}

type DateType struct{}

func (d DateType) Decode(payload []byte) (interface{}, error) {
	// Little endian 5 unsigned chars.
	// Based off of keepassx 0.4.3 source:
	// Kdb3Database.cpp: Kdb3Database::dateFromPackedStruct5
	//uchar = struct.unpack('<5B', payload)
	//year = (uchar[0] << 6) | (uchar[1] >> 2)
	//month = ((uchar[1] & 0x00000003) << 2) | (uchar[2] >> 6)
	//day = (uchar[2] >> 1) & 0x0000001F
	//hour = ((uchar[2] & 0x00000001) << 4) | (uchar[3] >> 4)
	//minutes = ((uchar[3] & 0x0000000F) << 2) | (uchar[4] >> 6)
	//seconds = uchar[4] & 0x0000003F
	//return datetime.datetime(year, month, day, hour, minutes, seconds)

	//quint32 dw1, dw2, dw3, dw4, dw5;
	//dw1 = (quint32)pBytes[0]; dw2 = (quint32)pBytes[1]; dw3 = (quint32)pBytes[2];
	//dw4 = (quint32)pBytes[3]; dw5 = (quint32)pBytes[4];
	//int y = (dw1 << 6) | (dw2 >> 2);
	//int mon = ((dw2 & 0x00000003) << 2) | (dw3 >> 6);
	//int d = (dw3 >> 1) & 0x0000001F;
	//int h = ((dw3 & 0x00000001) << 4) | (dw4 >> 4);
	//int min = ((dw4 & 0x0000000F) << 2) | (dw5 >> 6);
	//int s = dw5 & 0x0000003F;
	//return QDateTime(QDate(y,mon,d),QTime(h,min,s));
	dw1 := binary.LittleEndian.Uint64(payload[0:8])
	_ = binary.LittleEndian.Uint64(payload[8:16])
	_ = binary.LittleEndian.Uint64(payload[16:24])
	_ = binary.LittleEndian.Uint64(payload[24:32])
	_ = binary.LittleEndian.Uint64(payload[32:40])
	spew.Dump(dw1)
	return time.Now(), nil
}

type Group struct {
	ignored bool
	id      uint32
	name    string
	imageid uint32
	level   uint16
	flags   uint32
}

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
	group           Group
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
	data := make([]byte, len(content))
	if encryption_type != "Rijndael" {
		return data, errors.New(fmt.Sprintf("Unsupported encryption type: %s", encryption_type))
	}
	decryptor, err := aes.NewCipher(key)
	if err != nil {
		return data, err
	}
	mode := cipher.NewCBCDecrypter(decryptor, iv[:])
	mode.CryptBlocks(data, content)
	return data, err
}

func (k *KeepassXDatabase) calculateKey() ([]byte, error) {
	// TODO: support keyfile
	key := Sha256([]byte(k.password))
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

func (k *KeepassXDatabase) parsePayload(payload []byte) error {
	groups, offset, err := k.parseGroups(payload)
	spew.Dump(groups)
	entries, err := k.parseEntries(payload[offset:])
	spew.Dump(entries)
	return err
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
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.id = i.(uint32)
			case 0x2:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.groupid = i.(uint32)
			case 0x3:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.imageid = i.(uint32)
			case 0x4:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.title = i.(string)
			case 0x5:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.url = i.(string)
			case 0x6:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.username = i.(string)
			case 0x7:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.password = i.(string)
			case 0x8:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.notes = i.(string)
			case 0x9:
				d := DateType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := d.Decode(data)
				if err != nil {
					return entries, err
				}
				e.creation_time = i.(time.Time)
			case 0xa:
				offset += field_size
			case 0xb:
				offset += field_size
			case 0xc:
				offset += field_size
			case 0xd:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return entries, err
				}
				e.binary_desc = i.(string)
			case 0xe:
				b := BaseType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := b.Decode(data)
				if err != nil {
					return entries, err
				}
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
			field_type := binary.LittleEndian.Uint16(payload[offset : offset+2])
			offset += 2
			field_size := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
			offset += 4
			switch field_type {
			case 0x1:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return groups, offset, err
				}
				g.id = i.(uint32)
			case 0x2:
				s := StringType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return groups, offset, err
				}
				g.name = i.(string)
			case 0x7:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return groups, offset, err
				}
				g.imageid = i.(uint32)
			case 0x8:
				s := ShortType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return groups, offset, err
				}
				g.level = i.(uint16)
			case 0x9:
				s := IntegerType{}
				data := payload[offset : offset+field_size]
				offset += field_size
				i, err := s.Decode(data)
				if err != nil {
					return groups, offset, err
				}
				g.flags = i.(uint32)
			case 0xffff:
				break out
			}
		}
		groups = append(groups, g)
	}
	return groups, offset, nil
}

func (k *KeepassXDatabase) ReadFrom(r io.Reader) (int64, error) {
	n, err := k.Metadata.ReadFrom(r)
	if err != nil {
		return n, err
	}
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return n, err
	}
	encryption_type := getEncryptionFlag(k.flags)
	key, err := k.calculateKey()
	if err != nil {
		return n, err
	}
	payload, err := k.decryptPayload(content, key, encryption_type, k.iv)
	if err != nil {
		return n, err
	}
	spew.Dump(payload)
	err = k.parsePayload(payload)
	if err != nil {
		return n, err
	}
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

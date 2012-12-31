package ldap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"regexp"
	"strings"
)

const (
	AddRecord    = 0
	ModifyRecord = 1
	ModDnRecord  = 2
	ModRdnRecord = 3
	DeleteRecord = 4
	EntryRecord  = 255
)

var LDIFDebug bool = false

var attrValueSep []byte = []byte{':'}
var versionRegex *regexp.Regexp
var charsetRegex *regexp.Regexp

var stdBase64 *base64.Encoding

func init() {
	versionRegex = regexp.MustCompile(`^version:\s+(\d+)`)
	charsetRegex = regexp.MustCompile(`^charset:\s+([^ ]+)`)
	stdBase64 = base64.StdEncoding
}

type LDIFRecord interface {
	RecordType() uint8
}

type LDIFReader struct {
	Version string
	Charset string
	Reader  *bufio.Reader

	NoMoreEntries bool
	EntryCount    uint64
}

func NewLDIFReader(reader io.Reader) (*LDIFReader, *Error) {
	lr := &LDIFReader{Reader: bufio.NewReader(reader)}
	return lr, nil
}

func (lr *LDIFReader) ReadLDIFEntry() (LDIFRecord, *Error) {
	if lr.NoMoreEntries {
		return nil, nil
	}
	ldiflines, err := lr.readLDIFEntryIntoSlice()
	if err != nil {
		return nil, err
	}
	if ldiflines == nil {
		return nil, nil
	}

	if bytes.EqualFold(ldiflines[0][0:7], []byte("version")) {
		lr.Version = string(versionRegex.Find(ldiflines[0]))
		return lr.ReadLDIFEntry()
	}
	if bytes.EqualFold(ldiflines[0][0:7], []byte("charset")) {
		lr.Charset = string(charsetRegex.Find(ldiflines[0]))
		return lr.ReadLDIFEntry()
	}
	return sliceToLDIFRecord(ldiflines)
}

func sliceToLDIFRecord(lines [][]byte) (LDIFRecord, *Error) {
	// var controls []Control
	var dn string
	var dataLineStart int // better name, after dn/controls/changetype
	recordtype := EntryRecord
LINES:
	for i, line := range lines {
		attrName, value, err := findAttrAndValue(line)
		if err != nil {
			return nil, err
		}
		switch {
		case i == 0 && bytes.EqualFold(attrName, []byte("dn")):
			dn = string(value)
			continue LINES
		case i == 0 && !bytes.EqualFold(attrName, []byte("dn")):
			return nil, NewError(ErrorLDIFRead, errors.New("'dn:' not at the start of line in LDIF record"))
		case bytes.EqualFold(attrName, []byte("changetype")):
			switch strings.ToLower(string(value)) {
			// check the record type, if one.
			case "add":
				recordtype = AddRecord
			case "modify":
				recordtype = ModifyRecord
			case "moddn":
				recordtype = ModDnRecord
			case "modrdn":
				recordtype = ModRdnRecord
			case "delete":
				recordtype = DeleteRecord

			}
			continue LINES
		case bytes.EqualFold(attrName, []byte("control")):
			//TODO handle controls
			continue LINES
		}
		dataLineStart = i
		break
	}
	// TODO - add all the missing record types i.e. almost all :)
	unsupportError := NewError(ErrorLDIFRead, errors.New("Unsupported LDIF record type"))
	switch recordtype {
	case AddRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, AddRecord, dataLineStart)
		}
		return nil, unsupportError
	case ModifyRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, ModifyRecord, dataLineStart)
		}
		return nil, unsupportError
	case ModDnRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, ModDnRecord, dataLineStart)
		}
		return nil, unsupportError
	case ModRdnRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, ModRdnRecord, dataLineStart)
		}
		return nil, unsupportError
	case DeleteRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, DeleteRecord, dataLineStart)
		}
		return nil, unsupportError
	case EntryRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, EntryRecord, dataLineStart)
		}
		return ldifLinesToEntryRecord(dn, lines[dataLineStart:])
	}
	return nil, NewError(ErrorLDIFRead, errors.New("Unkown LDIF record type"))
}

//type Entry struct {
//	DN         string
//	Attributes []*EntryAttribute
//}

//type EntryAttribute struct {
//	Name   string
//	Values []string
//}
func ldifLinesToEntryRecord(dn string, lines [][]byte) (LDIFRecord, *Error) {
	entry := new(Entry)
	entry.DN = dn
	entry.Attributes = make([]*EntryAttribute, 0)
	for _, line := range lines {
		bAttr, bValue, err := findAttrAndValue(line)
		attr := string(bAttr)
		if err != nil {
			return nil, err
		}
		if bAttr == nil && bValue == nil {
			continue // -
		}
		position := entry.GetAttributeIndex(attr)
		if position == -1 {
			eAttr := EntryAttribute{Name: attr, Values: []string{string(bValue)}}
			entry.Attributes = append(entry.Attributes, &eAttr)
		} else {
			entry.Attributes[position].Values =
				append(entry.Attributes[position].Values, string(bValue))
		}
		//log.Printf("processed: %s: %s\n", attr, string(bValue))
	}
	//fmt.Println(entry)
	return entry, nil
}

func findAttrAndValue(line []byte) (attr []byte, value []byte, err *Error) {
	var valueStart int
	colonLoc := bytes.Index(line, attrValueSep)
	base64 := false
	if line[0] == '-' {
		return
	}
	// find the location of first ':'
	if colonLoc == -1 {
		return nil, nil, NewError(ErrorLDIFRead, errors.New(": not found in LDIF attr line."))
	} else if line[colonLoc+1] == ':' { // base64 attr
		valueStart = colonLoc + 2
		if line[colonLoc+2] == ' ' {
			valueStart = colonLoc + 3
		}
		base64 = true
	} else { // normal
		valueStart = colonLoc + 1
		if line[colonLoc+1] == ' ' { // accomidate attr:value
			valueStart = colonLoc + 2
		}
	}

	attr = line[:colonLoc]

	if base64 {
		decodedValue := make([]byte, stdBase64.DecodedLen(len(line[valueStart:])))
		count, err := stdBase64.Decode(decodedValue, line[valueStart:])
		if err != nil || count == 0 {
			return nil, nil, NewError(ErrorLDIFRead, errors.New("Error decoding base64 value"))
		}
		value = decodedValue[:count]
	} else {
		value = line[valueStart:]
	}
	if LDIFDebug {
		log.Printf("findAttrAndValue: attr: [%s]", attr)
		log.Printf("findAttrAndValue:value: [%s]", string(value))
	}
	return
}

func (lr *LDIFReader) readLDIFEntryIntoSlice() ([][]byte, *Error) {
	entry := make([][]byte, 0, 10)
	linecount := -1
ENTRY:
	for {
		line, err := lr.Reader.ReadBytes('\n')
		// fmt.Printf("len=%d, err=%v, %s", len(line), err, line)
		if err != nil {
			if err == io.EOF {
				lr.NoMoreEntries = true
				if len(entry) == 0 {
					return nil, nil
				}
				break
			}
			return nil, NewError(ErrorLDIFRead, err)
		}

		if line[0] == '\n' || (line[0] == '\r' && line[1] == '\n') {
			if len(entry) == 0 {
				continue ENTRY
			}
			break
		}
		if line[0] == '#' { // comments
			continue ENTRY
		}
		if line[0] == ' ' || line[0] == '\t' { // continuation
			if line[len(line)-2] == '\r' {
				entry[linecount] = append(entry[linecount], line[1:len(line)-2]...) // strip two bytes
			} else {
				entry[linecount] = append(entry[linecount], line[1:len(line)-1]...)
			}
			continue ENTRY
		}
		linecount++
		if line[len(line)-2] == '\r' {
			entry = append(entry, line[:len(line)-2]) // strip two bytes
		} else {
			entry = append(entry, line[:len(line)-1])
		}
		if err != nil {
			break ENTRY
		}
	}
	//for i, line := range entry {
	//	fmt.Println(i)
	//	fmt.Println(hex.Dump(line))
	//}
	return entry, nil
}

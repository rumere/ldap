package ldap

import (
	"bytes"
	"fmt"
	//"io"
	"strings"
	"testing"
)

func TestLdifWriter(t *testing.T) {
	fmt.Printf("TestLdifWriter: starting...\n")
	reader := strings.NewReader(simpleLDIF)
	lr, err := NewLDIFReader(reader)
	if err != nil {
		t.Error(err)
	}

	buf := new(bytes.Buffer)
	lw, lwerr := NewLDIFWriter(buf)
	if lwerr != nil {
		t.Error(err)
	}

	for {
		record, lerr := lr.ReadLDIFEntry()
		if lerr != nil {
			t.Errorf("Error reading LDIF: " + lerr)
			break
		}
		if record == nil {
			break
		}

		err = lw.WriteLDIFRecord(record)
		if err != nil {
			t.Error(err)
		}
		fmt.Print(buf.String())
		buf.Truncate(0)
	}
	fmt.Printf("TestLdifWriter: ended.\n")
}

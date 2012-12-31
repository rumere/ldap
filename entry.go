// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Entry structures and functions
package ldap

type Entry struct {
	DN         string
	Attributes []*EntryAttribute
}

type EntryAttribute struct {
	Name   string
	Values []string
}

func (req *Entry) RecordType() uint8 {
	return EntryRecord
}

func (e *Entry) GetAttributeValues(Attribute string) []string {
	for _, attr := range e.Attributes {
		if attr.Name == Attribute {
			return attr.Values
		}
	}

	return []string{}
}

func (e *Entry) GetAttributeValue(Attribute string) string {
	values := e.GetAttributeValues(Attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (e *Entry) GetAttributeIndex(Attribute string) int {
	for i, attr := range e.Attributes {
		if attr.Name == Attribute {
			return i
		}
	}
	return -1
}

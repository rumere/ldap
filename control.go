// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"fmt"
	"github.com/hsoj/asn1-ber"
)

const (
	//1.2.826.0.1.3344810.2.3
	//1.2.840.113556.1.4.1413
	ControlTypePaging = "1.2.840.113556.1.4.319"

//1.2.840.113556.1.4.473
//1.2.840.113556.1.4.805
//1.3.6.1.1.12
//1.3.6.1.1.13.1
//1.3.6.1.1.13.2
//1.3.6.1.4.1.26027.1.5.2
//1.3.6.1.4.1.42.2.27.8.5.1
//1.3.6.1.4.1.42.2.27.9.5.2
//1.3.6.1.4.1.42.2.27.9.5.8
//1.3.6.1.4.1.4203.1.10.1
//1.3.6.1.4.1.4203.1.10.2
//1.3.6.1.4.1.7628.5.101.1
//2.16.840.1.113730.3.4.12
//2.16.840.1.113730.3.4.16
//2.16.840.1.113730.3.4.17
//2.16.840.1.113730.3.4.18
//2.16.840.1.113730.3.4.19
//2.16.840.1.113730.3.4.2
//2.16.840.1.113730.3.4.3
//2.16.840.1.113730.3.4.4
//2.16.840.1.113730.3.4.5
//2.16.840.1.113730.3.4.9
)

var ControlTypeMap = map[string]string{
	ControlTypePaging: "Paging",
}

type Control interface {
	GetControlType() string
	Encode() *ber.Packet
	String() string
}

type ControlString struct {
	ControlType  string
	Criticality  bool
	ControlValue string
}

func (c *ControlString) GetControlType() string {
	return c.ControlType
}

func (c *ControlString) Encode() (p *ber.Packet) {
	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, c.ControlType, "Control Type ("+ControlTypeMap[c.ControlType]+")"))
	if c.Criticality {
		p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, c.ControlValue, "Control Value"))
	return
}

func (c *ControlString) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %s  Control Value: %s", ControlTypeMap[c.ControlType], c.ControlType, c.Criticality, c.ControlValue)
}

type ControlPaging struct {
	PagingSize uint32
	Cookie     []byte
}

func (c *ControlPaging) GetControlType() string {
	return ControlTypePaging
}

func (c *ControlPaging) Encode() (p *ber.Packet) {
	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, ControlTypePaging, "Control Type ("+ControlTypeMap[ControlTypePaging]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(c.PagingSize), "Paging Size"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	p.AppendChild(p2)
	return
}

func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %s  PagingSize: %d  Cookie: %q",
		ControlTypeMap[ControlTypePaging],
		ControlTypePaging,
		false,
		c.PagingSize,
		c.Cookie)
}

func (c *ControlPaging) SetCookie(Cookie []byte) {
	c.Cookie = Cookie
}

func FindControl(Controls []Control, ControlType string) Control {
	for _, c := range Controls {
		if c.GetControlType() == ControlType {
			return c
		}
	}
	return nil
}

func DecodeControl(p *ber.Packet) Control {
	ControlType := p.Children[0].Value.(string)
	Criticality := false

	p.Children[0].Description = "Control Type (" + ControlTypeMap[ControlType] + ")"
	value := p.Children[1]
	if len(p.Children) == 3 {
		value = p.Children[2]
		p.Children[1].Description = "Criticality"
		Criticality = p.Children[1].Value.(bool)
	}

	value.Description = "Control Value"
	switch ControlType {
	case ControlTypePaging:
		value.Description += " (Paging)"
		c := new(ControlPaging)
		if value.Value != nil {
			value_children := ber.DecodePacket(value.Data.Bytes())
			value.Data.Truncate(0)
			value.Value = nil
			value.AppendChild(value_children)
		}
		value = value.Children[0]
		value.Description = "Search Control Value"
		value.Children[0].Description = "Paging Size"
		value.Children[1].Description = "Cookie"
		c.PagingSize = uint32(value.Children[0].Value.(uint64))
		c.Cookie = value.Children[1].Data.Bytes()
		value.Children[1].Value = c.Cookie
		return c
	}
	c := new(ControlString)
	c.ControlType = ControlType
	c.Criticality = Criticality
	c.ControlValue = value.Value.(string)
	return c
}

func NewControlString(ControlType string, Criticality bool, ControlValue string) *ControlString {
	return &ControlString{
		ControlType:  ControlType,
		Criticality:  Criticality,
		ControlValue: ControlValue,
	}
}

func NewControlPaging(PagingSize uint32) *ControlPaging {
	return &ControlPaging{PagingSize: PagingSize}
}

func encodeControls(Controls []Control) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range Controls {
		p.AppendChild(control.Encode())
	}
	return p
}

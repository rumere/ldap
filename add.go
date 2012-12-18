// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

type AddRequest struct {
	DN         string
	Attributes []EntryAttribute
	Controls   []Control
}

func (l *Conn) Add(addReq *AddRequest) *Error {
	messageID := l.nextMessageID()

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	encoded, err := encodeAddRequest(addReq)

	if err != nil {
		return err
	}

	packet.AppendChild(encoded)

	if addReq.Controls != nil && len(addReq.Controls) > 0 {
		controls, err := encodeControls(addReq.Controls)
		if err != nil {
			return err
		}
		packet.AppendChild(controls)
	}

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)

	if err != nil {
		return err
	}

	if channel == nil {
		return NewError(ErrorNetwork, errors.New("Could not send message"))
	}

	defer l.finishMessage(messageID)
	if l.Debug {
		fmt.Printf("%d: waiting for response\n", messageID)
	}

	packet = <-channel

	if l.Debug {
		fmt.Printf("%d: got response %p\n", messageID, packet)
	}

	if packet == nil {
		return NewError(ErrorNetwork, errors.New("Could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return NewError(ErrorDebugging, err)
		}
		ber.PrintPacket(packet)
	}

	result_code, result_description := getLDAPResultCode(packet)

	if result_code != 0 {
		return NewError(result_code, errors.New(result_description))
	}

	if l.Debug {
		fmt.Printf("%d: returning\n", messageID)
	}
	// success
	return nil
}

/*
   AddRequest ::= [APPLICATION 8] SEQUENCE {
        entry           LDAPDN,
        attributes      AttributeList }

   AttributeList ::= SEQUENCE OF attribute Attribute

   Attribute ::= SEQUENCE {
        type       AttributeDescription,
        vals       SET OF value AttributeValue } // vals is not empty
*/
func encodeAddRequest(addReq *AddRequest) (*ber.Packet, *Error) {
	addPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, ApplicationMap[ApplicationAddRequest])
	addPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, addReq.DN, "LDAP DN"))

	attributeList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AttributeList")

	for _, attr := range addReq.Attributes {
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, attr.Name, "Attribute Desc"))
		if len(attr.Values) == 0 {
			return nil, NewError(ErrorEncoding, errors.New("Attribute "+attr.Name+" had no values."))
		}
		valuesSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Value Set")
		for _, val := range attr.Values {
			valuesSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, val, "AttributeValue"))
		}
		attribute.AppendChild(valuesSet)
		attributeList.AppendChild(attribute)
	}
	addPacket.AppendChild(attributeList)
	return addPacket, nil
}

func (req *AddRequest) Bytes() []byte {
	encoded, _ := encodeAddRequest(req)
	return encoded.Bytes()
}

func NewAddRequest(dn string) (req *AddRequest) {
	req = &AddRequest{DN: dn, Attributes: make([]EntryAttribute, 0, 5), Controls: make([]Control, 0)}
	return
}

func (req *AddRequest) AddAttribute(attr *EntryAttribute) {
	req.Attributes = append(req.Attributes, *attr)
}

func (req *AddRequest) AddAttributes(attrs []EntryAttribute) {
	req.Attributes = append(req.Attributes, attrs...)
}

// Basic LDIF dump, no formating, etc
func (addReq *AddRequest) DumpAddRequest() (dump string) {
	dump = fmt.Sprintf("dn: %s\n", addReq.DN)
	for _, attr := range addReq.Attributes {
		for _, val := range attr.Values {
			dump += fmt.Sprintf("%s: %s\n", attr.Name, val)
		}
	}
	dump += fmt.Sprintf("\n")
	return
}

func (req *AddRequest) AddControl(control Control) {
	if req.Controls == nil {
		req.Controls = make([]Control, 0)
	}
	req.Controls = append(req.Controls, control)
}

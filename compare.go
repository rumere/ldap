// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"github.com/mavricknz/asn1-ber"
)

/*
CompareRequest ::= [APPLICATION 14] SEQUENCE {
    entry           LDAPDN,
    ava             AttributeValueAssertion }

AttributeValueAssertion ::= SEQUENCE {
    attributeDesc   AttributeDescription,
    assertionValue  AssertionValue }
*/

type CompareRequest struct {
	DN       string
	Name     string
	Value    string
	Controls []Control
}

func (l *LDAPConnection) Compare(req *CompareRequest) *Error {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewError(ErrorClosing, errors.New("MessageID channel is closed."))
	}

	encodedCompare, err := encodeCompareRequest(req)
	if err != nil {
		return err
	}

	packet, err := requestBuildPacket(messageID, encodedCompare, req.Controls)
	if err != nil {
		return err
	}

	// CompareTrue = 6, CompareFalse = 5
	// returns an "Error"
	return l.sendReqRespPacket(messageID, packet)
}

func encodeCompareRequest(req *CompareRequest) (*ber.Packet, *Error) {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationCompareRequest, nil, ApplicationMap[ApplicationCompareRequest])
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.DN, "LDAP DN"))
	ava, err := encodeItem([]string{req.Name, "=", req.Value})
	if err != nil {
		return nil, err
	}
	p.AppendChild(ava)
	return p, nil
}

func NewCompareRequest(dn, name, value string) (req *CompareRequest) {
	req = &CompareRequest{DN: dn, Name: name, Value: value, Controls: make([]Control, 0)}
	return
}

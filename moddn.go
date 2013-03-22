// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

//ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//entry           LDAPDN,
//newrdn          RelativeLDAPDN,
//deleteoldrdn    BOOLEAN,
//newSuperior     [0] LDAPDN OPTIONAL }
//
//ModifyDNResponse ::= [APPLICATION 13] LDAPResult

type ModDnRequest struct {
	DN            string
	NewRDN        string
	DeleteOldDn   bool
	NewSuperiorDN string
	Controls      []Control
}

//Untested.
func (l *Conn) ModDn(modDnReq *ModDnRequest) *Error {
	messageID := l.nextMessageID()
	encodedModDn := encodeModDnRequest(modDnReq)

	packet, err := requestBuildPacket(messageID, encodedModDn, modDnReq.Controls)
	if err != nil {
		return err
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

func encodeModDnRequest(req *ModDnRequest) (p *ber.Packet) {
	p = ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ApplicationModifyDNRequest, nil, ApplicationMap[ApplicationModifyDNRequest])
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.DN, "LDAPDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.NewRDN, "NewRDN"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, req.DeleteOldDn, "deleteoldrdn"))
	if len(req.NewSuperiorDN) > 0 {
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative,
			ber.TagOctetString, req.NewSuperiorDN, "NewSuperiorDN"))
	}
	return
}

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Search functionality
package ldap

import (
	"errors"
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
)

var ScopeMap = map[int]string{
	ScopeBaseObject:   "Base Object",
	ScopeSingleLevel:  "Single Level",
	ScopeWholeSubtree: "Whole Subtree",
}

const (
	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3
)

const (
	SearchResultEntry     = ApplicationSearchResultEntry
	SearchResultReference = ApplicationSearchResultReference
	SearchResultDone      = ApplicationSearchResultDone
)

var DerefMap = map[int]string{
	NeverDerefAliases:   "NeverDerefAliases",
	DerefInSearching:    "DerefInSearching",
	DerefFindingBaseObj: "DerefFindingBaseObj",
	DerefAlways:         "DerefAlways",
}

type Entry struct {
	DN         string
	Attributes []*EntryAttribute
}

type EntryAttribute struct {
	Name   string
	Values []string
}

type SearchResult struct {
	Entries   []*Entry
	Referrals []string
	Controls  []Control
}

type PartialSearchResult struct {
	Conn              *Conn
	MessageID         uint64
	ApplicationResult uint8
	Entry             *Entry
	Referrals         []string
	Controls          []Control
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

type SearchRequest struct {
	BaseDN       string
	Scope        int
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       string
	Attributes   []string
	Controls     []Control
}

func NewSearchRequest(
	BaseDN string,
	Scope, DerefAliases, SizeLimit, TimeLimit int,
	TypesOnly bool,
	Filter string,
	Attributes []string,
	Controls []Control,
) *SearchRequest {
	return &SearchRequest{
		BaseDN:       BaseDN,
		Scope:        Scope,
		DerefAliases: DerefAliases,
		SizeLimit:    SizeLimit,
		TimeLimit:    TimeLimit,
		TypesOnly:    TypesOnly,
		Filter:       Filter,
		Attributes:   Attributes,
		Controls:     Controls,
	}
}

func (l *Conn) SearchWithPaging(SearchRequest *SearchRequest, PagingSize uint32) (*SearchResult, *Error) {
	if SearchRequest.Controls == nil {
		SearchRequest.Controls = make([]Control, 0)
	}

	PagingControl := NewControlPaging(PagingSize)
	SearchRequest.Controls = append(SearchRequest.Controls, PagingControl)
	SearchResult := new(SearchResult)
	for {
		result, err := l.Search(SearchRequest)
		if l.Debug {
			fmt.Printf("Looking for Paging Control...\n")
		}
		if err != nil {
			return SearchResult, err
		}
		if result == nil {
			return SearchResult, NewError(ErrorNetwork, errors.New("Packet not received"))
		}

		for _, entry := range result.Entries {
			SearchResult.Entries = append(SearchResult.Entries, entry)
		}
		for _, referral := range result.Referrals {
			SearchResult.Referrals = append(SearchResult.Referrals, referral)
		}
		for _, control := range result.Controls {
			SearchResult.Controls = append(SearchResult.Controls, control)
		}

		if l.Debug {
			fmt.Printf("Looking for Paging Control...\n")
		}
		paging_result := FindControl(result.Controls, ControlTypePaging)
		if paging_result == nil {
			PagingControl = nil
			if l.Debug {
				fmt.Printf("Could not find paging control.  Breaking...\n")
			}
			break
		}

		cookie := paging_result.(*ControlPaging).Cookie
		if len(cookie) == 0 {
			PagingControl = nil
			if l.Debug {
				fmt.Printf("Could not find cookie.  Breaking...\n")
			}
			break
		}
		PagingControl.SetCookie(cookie)
	}

	if PagingControl != nil {
		if l.Debug {
			fmt.Printf("Abandoning Paging...\n")
		}
		PagingControl.PagingSize = 0
		l.Search(SearchRequest)
	}

	return SearchResult, nil
}

func (l *Conn) Search(SearchRequest *SearchRequest) (*SearchResult, *Error) {
	messageID := l.nextMessageID()
	searchPacket, err := encodeSearchRequest(SearchRequest)
	if err != nil {
		return nil, err
	}

	packet, err := requestBuildPacket(messageID, searchPacket, SearchRequest.Controls)
	if err != nil {
		return nil, err
	}

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	if channel == nil {
		return nil, NewError(ErrorNetwork, errors.New("Could not send message"))
	}
	defer l.finishMessage(messageID)

	result := &SearchResult{
		Entries:   make([]*Entry, 0),
		Referrals: make([]string, 0),
		Controls:  make([]Control, 0)}

Search:
	for {
		if l.Debug {
			fmt.Printf("%d: waiting for response\n", messageID)
		}
		packet = <-channel
		if l.Debug {
			fmt.Printf("%d: got response %p\n", messageID, packet)
		}
		if packet == nil {
			return nil, NewError(ErrorNetwork, errors.New("Could not retrieve message"))
		}

		if l.Debug {
			if err := addLDAPDescriptions(packet); err != nil {
				return nil, NewError(ErrorDebugging, err)
			}
			ber.PrintPacket(packet)
		}

		partialSearchResult, err := decodeSearchResponse(packet)
		if err != nil {
			return result, err
		}

		switch partialSearchResult.ApplicationResult {
		case SearchResultEntry:
			result.Entries = append(result.Entries, partialSearchResult.Entry)
		case SearchResultDone:
			if partialSearchResult.Controls != nil {
				result.Controls = append(result.Controls, partialSearchResult.Controls...)
			}
			break Search
		case SearchResultReference:
			result.Referrals = append(result.Referrals, partialSearchResult.Referrals...)
		}
	}
	if l.Debug {
		fmt.Printf("%d: returning\n", messageID)
	}

	return result, nil
}

func encodeSearchRequest(req *SearchRequest) (*ber.Packet, *Error) {
	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.BaseDN, "Base DN"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(req.Scope), "Scope"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(req.DerefAliases), "Deref Aliases"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(req.SizeLimit), "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(req.TimeLimit), "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, req.TypesOnly, "Types Only"))
	filterPacket, err := CompileFilter(req.Filter)
	if err != nil {
		return nil, err
	}
	searchRequest.AppendChild(filterPacket)
	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range req.Attributes {
		attributesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, attribute, "Attribute"))
	}
	searchRequest.AppendChild(attributesPacket)
	return searchRequest, nil
}

func (req *SearchRequest) AddControl(control Control) {
	if req.Controls == nil {
		req.Controls = make([]Control, 0)
	}
	req.Controls = append(req.Controls, control)
}

// Experimental - not sure of API.
// Process the searchRequest using a callback. Uses less memory than Search(...).
// Can process individual results as they are returned.
// stopProcessing - indicates either way to stop/cleanup as request will not continue
// finished - optional channel for if calling as go routine.
// Example callback.
//
//countResults := 0
//cback := func(partRes *PartialSearchResult, err *Error, stopProcessing *bool) {
//	if err != nil {
//		fmt.Println(err)
//		return
//	}

//	switch partRes.ApplicationResult {
//	case SearchResultEntry:
//		fmt.Println("result entry")
//		countResults++
//	case SearchResultDone:
//		fmt.Println("results done")
//	case SearchResultReference:
//		fmt.Println("result referral")
//	}
//	return
//}
//finished := make(chan bool)
//go l.SearchWithCallback(search_request, cback, finished)
//<-finished
//fmt.Println(countResults)
//// or sequential
//countResults = 0
//l.SearchWithCallback(search_request, cback, nil)
//fmt.Println(countResults)
func (l *Conn) SearchWithCallback(
	searchRequest *SearchRequest,
	callback func(partialSearchResult *PartialSearchResult, error *Error, stopProcessing *bool),
	finished chan<- bool,
) {

	messageID := l.nextMessageID()
	stopProcessing := true // anything before read loop is an err.
	searchPacket, err := encodeSearchRequest(searchRequest)
	if err != nil {
		callback(nil, err, &stopProcessing)
		go sendFinished(finished)
		return
	}

	packet, err := requestBuildPacket(messageID, searchPacket, searchRequest.Controls)
	if err != nil {
		callback(nil, err, &stopProcessing)
		go sendFinished(finished)
		return
	}

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)
	if err != nil {
		callback(nil, err, &stopProcessing)
		go sendFinished(finished)
		return
	}
	if channel == nil {
		callback(nil, NewError(ErrorNetwork, errors.New("Could not send message")), &stopProcessing)
		go sendFinished(finished)
		return
	}
	defer l.finishMessage(messageID)
	stopProcessing = false
	for {
		if l.Debug {
			fmt.Printf("%d: waiting for response\n", messageID)
		}
		packet = <-channel
		if l.Debug {
			fmt.Printf("%d: got response %p\n", messageID, packet)
		}
		if packet == nil {
			stopProcessing = true
			callback(nil, NewError(ErrorNetwork, errors.New("Could not retrieve message")), &stopProcessing)
			go sendFinished(finished)
			return
		}

		if l.Debug {
			if err := addLDAPDescriptions(packet); err != nil {
				stopProcessing = true
				callback(nil, NewError(ErrorDebugging, err), &stopProcessing)
				go sendFinished(finished)
				return
			}
			ber.PrintPacket(packet)
		}

		partSearchResult, err := decodeSearchResponse(packet)
		if err != nil {
			stopProcessing = true
			callback(nil, err, &stopProcessing)
			go sendFinished(finished)
			return
		}
		partSearchResult.Conn = l
		partSearchResult.MessageID = messageID
		callback(partSearchResult, err, &stopProcessing)
		if partSearchResult.ApplicationResult == SearchResultDone || stopProcessing {
			break
		}
	}
	go sendFinished(finished)
	return
}

func sendFinished(fin chan<- bool) {
	if fin != nil {
		fin <- true
	}
}

// SearchResult decode to Entry,Controls,Referral
func decodeSearchResponse(packet *ber.Packet) (partialSearchResult *PartialSearchResult, err *Error) {
	partialSearchResult = new(PartialSearchResult)
	switch packet.Children[1].Tag {
	case SearchResultEntry:
		partialSearchResult.ApplicationResult = SearchResultEntry
		entry := new(Entry)
		entry.DN = packet.Children[1].Children[0].Value.(string)
		for _, child := range packet.Children[1].Children[1].Children {
			attr := new(EntryAttribute)
			attr.Name = child.Children[0].Value.(string)
			for _, value := range child.Children[1].Children {
				attr.Values = append(attr.Values, value.Value.(string))
			}
			entry.Attributes = append(entry.Attributes, attr)
		}
		partialSearchResult.Entry = entry
		return partialSearchResult, nil
	case SearchResultDone:
		partialSearchResult.ApplicationResult = SearchResultDone
		result_code, result_description := getLDAPResultCode(packet)
		if result_code != 0 {
			return partialSearchResult, NewError(result_code, errors.New(result_description))
		}

		if len(packet.Children) == 3 {
			controls := make([]Control, 0)
			for _, child := range packet.Children[2].Children {
				controls = append(controls, DecodeControl(child))
			}
			partialSearchResult.Controls = controls
		}
		return partialSearchResult, nil
	case SearchResultReference:
		partialSearchResult.ApplicationResult = SearchResultReference
		for ref := range packet.Children[1].Children {
			partialSearchResult.Referrals = append(partialSearchResult.Referrals, packet.Children[1].Children[ref].Value.(string))
		}
		return partialSearchResult, nil
	}
	return nil, NewError(ErrorDecoding, errors.New("Couldn't decode search result."))
}

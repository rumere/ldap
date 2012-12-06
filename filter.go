// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains a filter compiler/decompiler
/*
An LDAP search filter is defined in Section 4.5.1 of [RFC4511]
        Filter ::= CHOICE {
            and                [0] SET SIZE (1..MAX) OF filter Filter,
            or                 [1] SET SIZE (1..MAX) OF filter Filter,
            not                [2] Filter,
            equalityMatch      [3] AttributeValueAssertion,
            substrings         [4] SubstringFilter,
            greaterOrEqual     [5] AttributeValueAssertion,
            lessOrEqual        [6] AttributeValueAssertion,
            present            [7] AttributeDescription,
            approxMatch        [8] AttributeValueAssertion,
            extensibleMatch    [9] MatchingRuleAssertion }

        SubstringFilter ::= SEQUENCE {
            type    AttributeDescription,
            -- initial and final can occur at most once
            substrings    SEQUENCE SIZE (1..MAX) OF substring CHOICE {
             initial        [0] AssertionValue,
             any            [1] AssertionValue,
             final          [2] AssertionValue } }

        AttributeValueAssertion ::= SEQUENCE {
            attributeDesc   AttributeDescription,
            assertionValue  AssertionValue }

        MatchingRuleAssertion ::= SEQUENCE {
            matchingRule    [1] MatchingRuleId OPTIONAL,
            type            [2] AttributeDescription OPTIONAL,
            matchValue      [3] AssertionValue,
            dnAttributes    [4] BOOLEAN DEFAULT FALSE }

        AttributeDescription ::= LDAPString
                        -- Constrained to <attributedescription>
                        -- [RFC4512]

        AttributeValue ::= OCTET STRING

        MatchingRuleId ::= LDAPString

        AssertionValue ::= OCTET STRING

        LDAPString ::= OCTET STRING -- UTF-8 encoded,
                                    -- [Unicode] characters
*/
package ldap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/hsoj/asn1-ber"
	"regexp"
)

const (
	FilterAnd             = 0
	FilterOr              = 1
	FilterNot             = 2
	FilterEqualityMatch   = 3
	FilterSubstrings      = 4
	FilterGreaterOrEqual  = 5
	FilterLessOrEqual     = 6
	FilterPresent         = 7
	FilterApproxMatch     = 8
	FilterExtensibleMatch = 9
)

var FilterMap = map[uint64]string{
	FilterAnd:             "And",
	FilterOr:              "Or",
	FilterNot:             "Not",
	FilterEqualityMatch:   "Equality Match",
	FilterSubstrings:      "Substrings",
	FilterGreaterOrEqual:  "Greater Or Equal",
	FilterLessOrEqual:     "Less Or Equal",
	FilterPresent:         "Present",
	FilterApproxMatch:     "Approx Match",
	FilterExtensibleMatch: "Extensible Match",
}

const (
	FilterSubstringsInitial = 0
	FilterSubstringsAny     = 1
	FilterSubstringsFinal   = 2
)

var FilterSubstringsMap = map[uint64]string{
	FilterSubstringsInitial: "Substrings Initial",
	FilterSubstringsAny:     "Substrings Any",
	FilterSubstringsFinal:   "Substrings Final",
}

const (
	TagMatchingRule      = 1
	TagMatchingType      = 2
	TagMatchValue        = 3
	TagMatchDnAttributes = 4
)

const (
	FilterItem = 256
)

var FilterComponent = map[string]uint64{
	"&":  FilterAnd,
	"|":  FilterOr,
	"!":  FilterNot,
	"=":  FilterEqualityMatch,
	">=": FilterGreaterOrEqual,
	"<=": FilterLessOrEqual,
	"~=": FilterApproxMatch,
}

var opRegex *regexp.Regexp
var endRegex *regexp.Regexp
var itemRegex *regexp.Regexp
var unescapedWildCardRegex *regexp.Regexp
var wildCardSearchRegex *regexp.Regexp

var FilterDebug bool = false

func init() {
	opRegex = regexp.MustCompile(`^\(\s*([&!|])\s*`)
	endRegex = regexp.MustCompile(`^\)\s*`)
	itemRegex = regexp.MustCompile(
		`^\(\s*([-;.:\d\w]*[-;\d\w])\s*([:~<>]?=)((?:\\.|[^\\()]+)*)\)\s*`)
	unescapedWildCardRegex = regexp.MustCompile(`^(\\.|[^\\*]+)*\*`)
	wildCardSearchRegex = regexp.MustCompile(`^((\\.|[^\\*]+)*)\*`)
}

func CompileFilter(filter string) (*ber.Packet, *Error) {
	if len(filter) == 0 {
		return nil, NewError(ErrorFilterCompile, errors.New("Filter of zero length"))
	}
	if filter[0] != '(' {
		return nil, NewError(ErrorFilterCompile, errors.New("Filter does not start with '('"))
	}
	return parse(filter)
}

func parse(filter string) (*ber.Packet, *Error) {
	var err *Error
	var pTmp1 *ber.Packet
	pos := 0
	bracketCount := 0

	p := make([]*ber.Packet, 0, 5)

	// Simple non recursive method to create ber packets.
	// If its an Op "&|!" then push onto the stack
	// If its am filter expression (item) then add as a child
	// if its an ending ) pop the stack adding as child to above.
	// plus special cases of course.

	for {
		if matches := opRegex.FindStringSubmatch(filter[pos:]); len(matches) != 0 {
			pos += len(matches[0])
			pTmp1, err = encode(FilterComponent[matches[1]], nil)
			if err != nil {
				return nil, err
			}
			p = append(p, pTmp1)
			bracketCount++
			continue
		} else if matches := endRegex.FindStringSubmatch(filter[pos:]); len(matches) != 0 {
			if bracketCount <= 0 {
				return nil, NewError(ErrorFilterCompile,
					errors.New("Finished compiling filter with extra at end :"+
						fmt.Sprint(filter[pos:])))
			}
			bracketCount--
			pos += len(matches[0])
			pTmp1 = p[len(p)-1] // copy last *ber (sequence of values)
			if len(p) > 1 {     // not root of "tree"
				p[len(p)-2].AppendChild(pTmp1) // add as child to previous op
				p = p[:len(p)-1]               // pop stack
			}
			continue
		} else if matches := itemRegex.FindStringSubmatch(filter[pos:]); len(matches) != 0 {
			pos += len(matches[0])
			pTmp1, err = encode(FilterItem, matches[1:4])
			if err != nil {
				return nil, err
			}
			if len(p) == 0 { // case (attr=yyyy)
				p = append(p, pTmp1)
			} else {
				p[len(p)-1].AppendChild(pTmp1)
			}
			continue
		}
		break
	}
	//if len(p) > 0 {
	//	ber.PrintPacket(p[0])
	//}
	if len(filter[pos:]) > 0 {
		return nil, NewError(ErrorFilterCompile, errors.New(filter+" : Error compiling filter, invalid filter : "+fmt.Sprint(filter[pos:])))
	}
	return p[0], nil
}

func encode(opType uint64, value []string) (*ber.Packet, *Error) {
	var p *ber.Packet = nil
	var err *Error

	switch opType {
	case FilterAnd:
		if FilterDebug {
			fmt.Println("FilterAnd")
		}
		p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterAnd, nil, FilterMap[FilterAnd])
	case FilterOr:
		if FilterDebug {
			fmt.Println("FilterOr")
		}
		p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterOr, nil, FilterMap[FilterOr])
	case FilterNot:
		if FilterDebug {
			fmt.Println("FilterNot")
		}
		p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterNot, nil, FilterMap[FilterNot])
	case FilterItem:
		if FilterDebug {
			fmt.Println("FilterItem")
		}
		p, err = encodeItem(value)
	}
	return p, err
}

func encodeItem(attrOpVal []string) (*ber.Packet, *Error) {
	attr, op, val := attrOpVal[0], attrOpVal[1], attrOpVal[2]
	if FilterDebug {
		fmt.Println(attr, op, val)
	}

	if op == ":=" {
		return encodeExtensibleMatch(attr, val)
	}

	if op == "=" {
		if val == "*" { // simple present
			p := ber.NewString(ber.ClassContext, ber.TypePrimative, FilterPresent, attr, FilterMap[FilterPresent])
			return p, nil
		} else if unescapedWildCardRegex.Match([]byte(val)) {
			// TODO ADD escaping.
			return encodeSubStringMatch(attr, val)
		}
	}

	// AttributeValueAssertion seq of the ritght op.
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed,
		uint8(FilterComponent[op]), nil, FilterMap[FilterComponent[op]])
	p.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimative,
			ber.TagOctetString, attr, "Attribute"))
	p.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimative,
			ber.TagOctetString, val, "Value"))

	return p, nil
}

/*
substrings         [4] SubstringFilter,

SubstringFilter ::= SEQUENCE {
            type    AttributeDescription,
            -- initial and final can occur at most once
            substrings    SEQUENCE SIZE (1..MAX) OF substring CHOICE {
             initial        [0] AssertionValue,
             any            [1] AssertionValue,
             final          [2] AssertionValue } }
*/

func encodeSubStringMatch(attr, value string) (*ber.Packet, *Error) {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed,
		FilterSubstrings, nil, FilterMap[FilterSubstrings])
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, attr, "type"))
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "substrings")

	pos := 0

	for {
		matches := wildCardSearchRegex.FindStringSubmatch(value[pos:])
		if FilterDebug {
			fmt.Println(matches)
		}

		// not match found return error

		if matches == nil && pos == 0 {
			if FilterDebug {
				fmt.Println("Did not match filter")
			}
			return nil, NewError(ErrorFilterCompile,
				errors.New("Did not match filter."))
		}
		// attr=*XXX
		if len(matches) == 0 {
			break
		}
		// initial
		if pos == 0 && len(matches[1]) > 0 {
			if FilterDebug {
				fmt.Println("initial : " + matches[1])
			}
			seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, FilterSubstringsInitial, matches[1], "initial"))
		}
		// past initial but not end
		if pos > 0 && len(matches) > 1 && len(matches[1]) > 0 {
			if FilterDebug {
				fmt.Println("any : " + matches[1])
			}
			seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, FilterSubstringsAny, matches[1], "any"))
		}

		pos += len(matches[0])
		if pos == len(value) {
			break
		}
	}
	if len(value[pos:]) > 0 {
		if FilterDebug {
			fmt.Println("final : " + value[pos:])
		}
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, FilterSubstringsFinal, value[pos:], "final"))
	}
	p.AppendChild(seq)
	if FilterDebug {
		fmt.Println(hex.Dump(p.Bytes()))
	}
	return p, nil
}

/*
extensibleMatch    [9] MatchingRuleAssertion

MatchingRuleAssertion ::= SEQUENCE {
            matchingRule    [1] MatchingRuleId OPTIONAL,
            type            [2] AttributeDescription OPTIONAL,
            matchValue      [3] AssertionValue,
            dnAttributes    [4] BOOLEAN DEFAULT FALSE }
*/

func encodeExtensibleMatch(attr, value string) (*ber.Packet, *Error) {
	//TODO make cacheable
	extenseRegex := regexp.MustCompile(`^([-;\d\w]*)(:dn)?(:(\w+|[.\d]+))?$`)
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed,
		FilterExtensibleMatch, nil, FilterMap[FilterExtensibleMatch])
	if matches := extenseRegex.FindStringSubmatch(attr); len(matches) != 0 {
		if FilterDebug {
			fmt.Println(matches)
		}
		rtype := matches[1]
		dn := matches[2]
		rule := matches[4]

		if len(rule) > 0 {
			prule := ber.NewString(ber.ClassContext, ber.TypePrimative, TagMatchingRule, rule, "matchingRule")
			p.AppendChild(prule)
		}
		if len(rtype) > 0 {
			ptype := ber.NewString(ber.ClassContext, ber.TypePrimative, TagMatchingType, rtype, "type")
			p.AppendChild(ptype)
		}
		// write an unescape
		pval := ber.NewString(ber.ClassContext, ber.TypePrimative, TagMatchValue, value, "matchValue")
		p.AppendChild(pval)
		if len(dn) > 0 {
			pdn := ber.NewBoolean(ber.ClassContext, ber.TypePrimative, TagMatchDnAttributes, true, "dnAttributes")
			p.AppendChild(pdn)
		}
	} else {
		return nil, NewError(ErrorFilterCompile,
			errors.New("Invalid Extensible attr : "+attr))
	}
	if FilterDebug {
		fmt.Println(hex.Dump(p.Bytes()))
	}
	return p, nil
}

// TODO: Really unescape
func unescape(raw string) string {
	return raw
}

// TODO: Really escape
func escape(raw string) string {
	return raw
}

func DecompileFilter(packet *ber.Packet) (ret string, err *Error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorFilterDecompile, errors.New("Error decompiling filter"))
		}
	}()
	ret = "("
	err = nil
	child_str := ""

	switch packet.Tag {
	case FilterAnd:
		ret += "&"
		for _, child := range packet.Children {
			child_str, err = DecompileFilter(child)
			if err != nil {
				return
			}
			ret += child_str
		}
	case FilterOr:
		ret += "|"
		for _, child := range packet.Children {
			child_str, err = DecompileFilter(child)
			if err != nil {
				return
			}
			ret += child_str
		}
	case FilterNot:
		ret += "!"
		child_str, err = DecompileFilter(packet.Children[0])
		if err != nil {
			return
		}
		ret += child_str

	case FilterSubstrings:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "="
		switch packet.Children[1].Children[0].Tag {
		case FilterSubstringsInitial:
			ret += ber.DecodeString(packet.Children[1].Children[0].Data.Bytes()) + "*"
		case FilterSubstringsAny:
			ret += "*" + ber.DecodeString(packet.Children[1].Children[0].Data.Bytes()) + "*"
		case FilterSubstringsFinal:
			ret += "*" + ber.DecodeString(packet.Children[1].Children[0].Data.Bytes())
		}
	case FilterEqualityMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterGreaterOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += ">="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterLessOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "<="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterPresent:
        ret += ber.DecodeString(packet.Data.Bytes())
		ret += "=*"
	case FilterApproxMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "~="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
    case FilterExtensibleMatch:
        // TODO
	}

	ret += ")"
	return
}

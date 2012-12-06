package ldap

import (
	"fmt"
	"testing"
)

var local_ldap_binddn string = "cn=directory manager"
var local_ldap_passwd string = "qwerty"
var local_ldap_server string = "localhost"
var local_ldap_port uint16 = 1389
var local_base_dn string = "dc=example,dc=com"
var local_filter []string = []string{
    "(uniqueMember=*)",
	"(|(uniqueMember=*)(sn=Abbie))",
	"(&(objectclass=person)(cn=ab*))",
	"(&(objectclass=person)(cn=ko*))",
    "(&(|(sn=an*)(sn=ba*))(!(sn=bar*)))"}

// go test -test.v -run="TestLocalSearch$" ldap
// Setup an OpenDJ server on port 1389 with 2000->20k default entries
// http://www.forgerock.org/opendj.html

var local_attributes []string = []string{
	"cn",
	"description"}

func TestLocalConnect(t *testing.T) {
	fmt.Printf("TestConnect: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()
	fmt.Printf("TestConnect: finished...\n")
}

func TestLocalSearch(t *testing.T) {
	fmt.Printf("TestSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
    
    // l.Debug = true
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()
    
    err = l.Bind(local_ldap_binddn, local_ldap_passwd)
    if err != nil {
		t.Errorf(err.Error())
		return
	}
	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[0],
		local_attributes,
		nil)
    // ber.Debug = true
	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestSearch: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
    //fmt.Printf("TestSearch: num of entries = %d\n\n",  len(sr.Entries))
}

func TestLocalSearchWithPaging(t *testing.T) {
	fmt.Printf("TestSearchWithPaging: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind("", "")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[1],
		local_attributes,
		nil)
	sr, err := l.SearchWithPaging(search_request, 5)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Printf("TestSearchWithPaging: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func testLocalMultiGoroutineSearch(t *testing.T, l *Conn, results chan *SearchResult, i int) {
	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[i],
		local_attributes,
		nil)
	sr, err := l.Search(search_request)

	if err != nil {
		t.Errorf(err.Error())
		results <- nil
		return
	}

	results <- sr
}

func TestLocalMultiGoroutineSearch(t *testing.T) {
	fmt.Printf("TestMultiGoroutineSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	results := make([]chan *SearchResult, len(local_filter))
	for i := range local_filter {
		results[i] = make(chan *SearchResult)
		go testLocalMultiGoroutineSearch(t, l, results[i], i)
	}
	for i := range local_filter {
		sr := <-results[i]
		if sr == nil {
			t.Errorf("Did not receive results from goroutine for %q", local_filter[i])
		} else {
			fmt.Printf("TestLocalMultiGoroutineSearch(%d): %s -> num of entries = %d\n", i, local_filter[i], len(sr.Entries))
		}
	}
}

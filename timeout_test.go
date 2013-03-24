package ldap

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"
)

func TestSearchTimeout(t *testing.T) {
	fmt.Printf("TestSearchTimeout: starting...\n")
	l := NewLDAPConnection(ldap_server, ldap_port)
	l.NetworkConnectTimeout = 5000 * time.Millisecond
	l.ReadTimeout = 30 * time.Second
	l.AbandonMessageOnReadTimeout = true
	err := l.Connect()

	if err != nil {
		t.Errorf(err.Error())
		return
	}
	if l == nil {
		t.Errorf("No Connection.")
		return
	}
	defer l.Close()

	search_request := NewSearchRequest(
		base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[0],
		attributes,
		nil)

	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestSearchTimeout: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func TestSearchTimeoutSSL(t *testing.T) {
	fmt.Printf("TestSearchTimeoutSSL: starting...\n")
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	l := &LDAPConnection{
		Addr:                  fmt.Sprintf("%s:%d", ldap_server, 636),
		IsSSL:                 true,
		TlsConfig:             config,
		NetworkConnectTimeout: 5000 * time.Millisecond,
		ReadTimeout:           30 * time.Second,
	}

	err := l.Connect()
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	search_request := NewSearchRequest(
		base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[0],
		attributes,
		nil)

	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestSearchTimeoutSSL: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

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
	`(&(objectclass=person)(cn=\41\42*))`, // same as above
	"(&(objectclass=person)(cn=ko*))",
	"(&(|(sn=an*)(sn=ba*))(!(sn=bar*)))",
	"(&(ou:dn:=people)(sn=aa*))"}

// go test -test.v -run="TestLocalSearch$" ldap
// Setup an OpenDJ server on port 1389 with 2000->20k default entries
// http://www.forgerock.org/opendj.html

var local_attributes []string = []string{
	"cn",
	"description"}

var local_addDNs []string = []string{"cn=Jon Boy,ou=People,dc=example,dc=com"}
var local_addAttrs []EntryAttribute = []EntryAttribute{
	EntryAttribute{
		Name: "objectclass",
		Values: []string{
			"person", "inetOrgPerson", "organizationalPerson", "top",
		},
	},
	EntryAttribute{
		Name: "cn",
		Values: []string{
			"Jon Boy",
		},
	},
	EntryAttribute{
		Name: "givenName",
		Values: []string{
			"Jon",
		},
	},
	EntryAttribute{
		Name: "sn",
		Values: []string{
			"Boy",
		},
	},
}

func TestLocalConnect(t *testing.T) {
	fmt.Printf("TestLocalConnect: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()
	fmt.Printf("TestLocalConnect: finished...\n")
}

func TestLocalSearch(t *testing.T) {
	fmt.Printf("TestLocalSearch: starting...\n")
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
	fmt.Printf("TestLocalSearch: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
	//fmt.Printf("TestSearch: num of entries = %d\n\n",  len(sr.Entries))
}

func TestLocalSearchWithPaging(t *testing.T) {
	fmt.Printf("TestLocalSearchWithPaging: starting...\n")
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

	fmt.Printf("TestLocalSearchWithPaging: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
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
	fmt.Printf("TestLocalMultiGoroutineSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
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

func TestLocalAddAndDelete(t *testing.T) {
	fmt.Printf("TestLocalAddAndDelete: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
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

	addReq := NewAddRequest(local_addDNs[0])
	for _, attr := range local_addAttrs {
		addReq.AddAttribute(&attr)
	}
	fmt.Printf("Adding: %s\n", local_addDNs[0])
	err = l.Add(addReq)
	if err != nil {
		t.Errorf("Add : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
	fmt.Printf("Deleting: %s\n", local_addDNs[0])
	delRequest := &DeleteRequest{local_addDNs[0], nil}
	err = l.Delete(delRequest)
	if err != nil {
		t.Errorf("Delete : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
}

func TestLocalPermissiveModifyRequest(t *testing.T) {
	fmt.Printf("LocalPermissiveModifyRequest: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
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

	addReq := NewAddRequest(local_addDNs[0])
	for _, attr := range local_addAttrs {
		addReq.AddAttribute(&attr)
	}
	fmt.Printf("Adding: %s\n", local_addDNs[0])
	err = l.Add(addReq)
	if err != nil {
		t.Errorf("Add : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
	modreq := NewModifyRequest(local_addDNs[0])
	mod := NewMod(ModAdd, "description", []string{"aaa"})
	modreq.AddMod(mod)
	fmt.Printf(modreq.DumpModRequest())
	err = l.Modify(modreq)
	if err != nil {
		t.Errorf("Modify : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	mod = NewMod(ModAdd, "description", []string{"aaa", "bbb", "ccc"})
	modreq = NewModifyRequest(local_addDNs[0])
	modreq.AddMod(mod)
	control := NewControlString(ControlTypePermissiveModifyRequest, true, "")
	fmt.Println(control.String())
	modreq.AddControl(control)
	fmt.Printf(modreq.DumpModRequest())
	err = l.Modify(modreq)
	if err != nil {
		t.Errorf("Modify (Permissive): %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	fmt.Printf("Deleting: %s\n", local_addDNs[0])
	delRequest := NewDeleteRequest(local_addDNs[0])
	err = l.Delete(delRequest)

	if err != nil {
		t.Errorf("Delete : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
}

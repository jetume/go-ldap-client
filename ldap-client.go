// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"time"
	"gopkg.in/ldap.v2"
)

type LDAPClient struct {
	Conn         *ldap.Conn
	Host         string
	Port         int
	UseSSL       bool
	BindDN       string
	BindPassword string
	GroupFilter  string // e.g. "(memberUid=%s)"
	UserFilter   string // e.g. "(uid=%s)"
	Base         string
	Attributes   []string
	ServerName   string
}

// Connect connects to the ldap backend
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				return err
			}
		} else {
			l, err = ldap.DialTLS("tcp", address, &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         lc.ServerName,
			})
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
	}
}

func (lc *LDAPClient) SearchUser(username string) (map[string]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		lc.Attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	
	retry := 3
	for err != nil && retry <= 3 {
	  sr, err = lc.Conn.Search(searchRequest)
	  log.Printf("Retrying: [%s:%d] \n", searchRequest, retry)
	  time.Sleep(time.Second * time.Duration(retry))
	  retry++
	}
	
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) < 1 {
		return nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return nil, errors.New("Too many entries returned")
	}

	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	return user, nil
}

// Authenticate authenticates the user against the ldap backend
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	return true, user, nil
}

// GetGroupsOfUser returns the group for a user
func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	
	retry := 3
	for err != nil && retry <= 3 {
	  sr, err = lc.Conn.Search(searchRequest)
	  log.Printf("Retrying: [%s:%d] \n", searchRequest, retry)
	  time.Sleep(time.Second * time.Duration(retry))
	  retry++
	}
	
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

func (lc *LDAPClient) FindUsers(search string) ([]map[string]string, error) {
  err := lc.Connect()
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, search),
		lc.Attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	
	retry := 3
	for err != nil && retry <= 3 {
	  sr, err = lc.Conn.Search(searchRequest)
	  log.Printf("Retrying: [%s:%d] \n", searchRequest, retry)
	  time.Sleep(time.Second * time.Duration(retry))
	  retry++
	}
	
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) < 1 {
		return nil, errors.New("User does not exist")
	}

	users := []map[string]string{}
	for _, ldap_user := range sr.Entries {
	  user := make(map[string]string)
	  for _, attr := range lc.Attributes {
  		user[attr] = ldap_user.GetAttributeValue(attr)
  	}
	  users = append(users, user)
	}

	return users, nil
}

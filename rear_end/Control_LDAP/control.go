package Control_LDAP

import (
	"log"

	"gopkg.in/ldap.v2"
)

// 删除用户
func Del(con *ldap.Conn, dn string) {
	del := ldap.NewDelRequest(dn, nil)
	err := con.Del(del)
	if err != nil {
		log.Fatal(err)
	}
}

// 添加用户
func Add(con *ldap.Conn, dn string, username string, userpassword string) {
	sql := ldap.NewAddRequest(dn)
	//Person属性必须有cn,sn,userPassword。
	sql.Attribute("cn", []string{username})
	sql.Attribute("sn", []string{username})
	sql.Attribute("userPassword", []string{"userpassword"})
	sql.Attribute("objectClass", []string{"Person"})

	err := con.Add(sql)
	//为用户添加LDAP属性
	/*type Attribute struct {
		// Type is the name of the LDAP attribute
		Type string
		// Vals are the LDAP attribute values
		Vals []string
	}*/
	if err != nil {
		log.Fatal(err)
	}
}

func Search(con *ldap.Conn, dn string) *ldap.SearchResult {
	sqt := ldap.NewSearchRequest(
		dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=person)(cn=Wind))", []string{"userPassword", "dn", "cn", "objectClass"}, nil)
	cur, err := con.Search(sqt)
	if err != nil {
		log.Fatal(err)
	}
	return cur
}

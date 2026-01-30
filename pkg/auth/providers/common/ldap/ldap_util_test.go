package ldap

import (
	"testing"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUserExternalID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc        string
		username    string
		loginDomain string
		want        string
	}{
		{
			desc:        "added login domain",
			username:    "user1",
			loginDomain: "Domain1",
			want:        "Domain1\\user1",
		},
		{
			desc:        "no login domain",
			username:    "user1",
			loginDomain: "",
			want:        "user1",
		},
		{
			desc:        "username already contains domain",
			username:    "Domain2\\user1",
			loginDomain: "Domain1",
			want:        "Domain2\\user1",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			externalID := GetUserExternalID(test.username, test.loginDomain)
			assert.Equal(t, test.want, externalID)
		})
	}
}

func TestSanitizeAttribute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		attr string
		want string
	}{
		// Whitespace.
		{"", ""},
		{"   ", ""},
		{" a- b", "a-b"},
		{"a\tb", "ab"},
		{"a\nb", "ab"},
		// Special characters.
		{"a#b$c'd(e)f+g,h;i<j=k>l\\m_n{o}p", "abcdefghijklmnop"},
		// Valid short names stay the same.
		{"a", "a"},
		{"a1", "a1"},
		{"a1-", "a1-"},
		{"a-b", "a-b"},
		{"a1-b2", "a1-b2"},
		{"1a", "1a"},
		{"-a", "-a"},
		{"-1a", "-1a"},
		{"1-a", "1-a"},
		// Valid numeric OIDs stay the same.
		{"1", "1"},
		{"1.2", "1.2"},
		{"1.2.3", "1.2.3"},
		{"123.456.789", "123.456.789"},
		{"12345678901234567890", "12345678901234567890"},
		{"1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20", "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20"},
		// Technically invalid identifiers.
		{"1ab", "1ab"},
		{"1.a.2", "1.a.2"},
		{".", "."},
		{"a.b", "a.b"},
		{"1-2-3", "1-2-3"},
	}

	for _, test := range tests {
		t.Run(test.attr, func(t *testing.T) {
			assert.Equal(t, test.want, SanitizeAttr(test.attr))
		})
	}
}
func TestIsValidAttribute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		attr  string
		valid bool
	}{
		{"", false},
		// Short names.
		{"a", true},
		{"a1", true},
		{"a1-", true},
		{"a-b", true},
		{"a1-b2", true},
		{"1a", false},
		{"-a", false},
		{"-1a", false},
		{"1-a", false},
		// Numeric OIDs.
		{"0", true},
		{"1", true},
		{"0.1", true},
		{"1.2", true},
		{"0.0.0", true},
		{"1.2.3", true},
		{"123.456.789", true},
		{"12345678901234567890", true},
		{"1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20", true},
		{".", false},
		{"1.", false},
		{"1..1", false},
		{"1.-1", false},
		{"01", false},
		{"1.02", false},
	}

	for _, test := range tests {
		t.Run(test.attr, func(t *testing.T) {
			assert.Equal(t, test.valid, IsValidAttr(test.attr))
		})
	}
}

func TestAttributesToPrincipal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		attribs            []*ldapv3.EntryAttribute
		dnStr              string
		scope              string
		providerName       string
		userObjectClass    string
		userNameAttribute  string
		userLoginAttribute string
		groupObjectClass   string
		groupNameAttribute string
		wantPrincipalName  string
		wantDisplayName    string
		wantLoginName      string
		wantPrincipalType  string
		wantProvider       string
		wantErr            bool
	}{
		{
			name: "user with login attribute - DN changes but login stays same (key test case)",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"inetOrgPerson", "person"}},
				{Name: "cn", Values: []string{"王磊"}},
				{Name: "uid", Values: []string{"wanglei"}},
			},
			dnStr:              "uid=wanglei,ou=dev,dc=example,dc=com",
			scope:              "openldap_user",
			providerName:       "openldap",
			userObjectClass:    "inetOrgPerson",
			userNameAttribute:  "cn",
			userLoginAttribute: "uid",
			groupObjectClass:   "groupOfNames",
			groupNameAttribute: "cn",
			wantPrincipalName:  "openldap_user://wanglei", // 使用 login 而不是完整 DN
			wantDisplayName:    "王磊",
			wantLoginName:      "wanglei",
			wantPrincipalType:  "user",
			wantProvider:       "openldap",
			wantErr:            false,
		},
		{
			name: "same user after moving to different OU - principalName should remain same",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"inetOrgPerson", "person"}},
				{Name: "cn", Values: []string{"王磊"}},
				{Name: "uid", Values: []string{"wanglei"}},
			},
			dnStr:              "uid=wanglei,ou=prod,dc=example,dc=com", // DN 改变了
			scope:              "openldap_user",
			providerName:       "openldap",
			userObjectClass:    "inetOrgPerson",
			userNameAttribute:  "cn",
			userLoginAttribute: "uid",
			groupObjectClass:   "groupOfNames",
			groupNameAttribute: "cn",
			wantPrincipalName:  "openldap_user://wanglei", // principalName 保持不变！
			wantDisplayName:    "王磊",
			wantLoginName:      "wanglei",
			wantPrincipalType:  "user",
			wantProvider:       "openldap",
			wantErr:            false,
		},
		{
			name: "user without login attribute - fallback to account name",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"person"}},
				{Name: "cn", Values: []string{"张三"}},
			},
			dnStr:              "cn=张三,ou=users,dc=example,dc=com",
			scope:              "openldap_user",
			providerName:       "openldap",
			userObjectClass:    "person",
			userNameAttribute:  "cn",
			userLoginAttribute: "uid",
			groupObjectClass:   "groupOfNames",
			groupNameAttribute: "cn",
			wantPrincipalName:  "openldap_user://张三", // 使用 accountName
			wantDisplayName:    "张三",
			wantLoginName:      "张三",
			wantPrincipalType:  "user",
			wantProvider:       "openldap",
			wantErr:            false,
		},
		{
			name: "user without any name attributes - fallback to DN",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"person"}},
			},
			dnStr:              "uid=user1,dc=example,dc=com",
			scope:              "openldap_user",
			providerName:       "openldap",
			userObjectClass:    "person",
			userNameAttribute:  "cn",
			userLoginAttribute: "uid",
			groupObjectClass:   "groupOfNames",
			groupNameAttribute: "cn",
			wantPrincipalName:  "openldap_user://uid=user1,dc=example,dc=com", // 完全回退到 DN
			wantDisplayName:    "",                                             // accountName 为空，因为没有匹配的属性
			wantLoginName:      "",                                             // login 为空
			wantPrincipalType:  "user",
			wantProvider:       "openldap",
			wantErr:            false,
		},
		{
			name: "user with empty login attribute value - fallback to account name",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"person"}},
				{Name: "cn", Values: []string{"李四"}},
				{Name: "uid", Values: []string{""}}, // 空值
			},
			dnStr:              "cn=李四,ou=users,dc=example,dc=com",
			scope:              "openldap_user",
			providerName:       "openldap",
			userObjectClass:    "person",
			userNameAttribute:  "cn",
			userLoginAttribute: "uid",
			groupObjectClass:   "groupOfNames",
			groupNameAttribute: "cn",
			wantPrincipalName:  "openldap_user://李四",
			wantDisplayName:    "李四",
			wantLoginName:      "李四",
			wantPrincipalType:  "user",
			wantProvider:       "openldap",
			wantErr:            false,
		},
		{
			name: "group should still use DN (not login)",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"groupOfNames"}},
				{Name: "cn", Values: []string{"developers"}},
			},
			dnStr:              "cn=developers,ou=groups,dc=example,dc=com",
			scope:              "openldap_group",
			providerName:       "openldap",
			userObjectClass:    "person",
			userNameAttribute:  "cn",
			userLoginAttribute: "uid",
			groupObjectClass:   "groupOfNames",
			groupNameAttribute: "cn",
			wantPrincipalName:  "openldap_group://cn=developers,ou=groups,dc=example,dc=com", // 组仍使用 DN
			wantDisplayName:    "developers",
			wantLoginName:      "developers",
			wantPrincipalType:  "group",
			wantProvider:       "openldap",
			wantErr:            false,
		},
		{
			name: "Active Directory user with sAMAccountName",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"user", "person"}},
				{Name: "cn", Values: []string{"John Doe"}},
				{Name: "sAMAccountName", Values: []string{"jdoe"}},
			},
			dnStr:              "CN=John Doe,OU=IT,OU=Users,DC=corp,DC=example,DC=com",
			scope:              "activedirectory_user",
			providerName:       "activedirectory",
			userObjectClass:    "user",
			userNameAttribute:  "cn",
			userLoginAttribute: "sAMAccountName",
			groupObjectClass:   "group",
			groupNameAttribute: "cn",
			wantPrincipalName:  "activedirectory_user://jdoe", // 使用 sAMAccountName
			wantDisplayName:    "John Doe",
			wantLoginName:      "jdoe",
			wantPrincipalType:  "user",
			wantProvider:       "activedirectory",
			wantErr:            false,
		},
		{
			name: "neither user nor group object class - should error",
			attribs: []*ldapv3.EntryAttribute{
				{Name: "objectClass", Values: []string{"unknown"}},
			},
			dnStr:              "cn=test,dc=example,dc=com",
			scope:              "openldap_user",
			providerName:       "openldap",
			userObjectClass:    "person",
			userNameAttribute:  "cn",
			userLoginAttribute: "uid",
			groupObjectClass:   "groupOfNames",
			groupNameAttribute: "cn",
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			principal, err := AttributesToPrincipal(
				tt.attribs,
				tt.dnStr,
				tt.scope,
				tt.providerName,
				tt.userObjectClass,
				tt.userNameAttribute,
				tt.userLoginAttribute,
				tt.groupObjectClass,
				tt.groupNameAttribute,
			)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, principal)

			assert.Equal(t, tt.wantPrincipalName, principal.ObjectMeta.Name, "principalName mismatch")
			assert.Equal(t, tt.wantDisplayName, principal.DisplayName, "displayName mismatch")
			assert.Equal(t, tt.wantLoginName, principal.LoginName, "loginName mismatch")
			assert.Equal(t, tt.wantPrincipalType, principal.PrincipalType, "principalType mismatch")
			assert.Equal(t, tt.wantProvider, principal.Provider, "provider mismatch")
			assert.True(t, principal.Me, "Me should be true")
		})
	}
}

// TestAttributesToPrincipal_OrgChangeScenario 测试用户换组织的场景
func TestAttributesToPrincipal_OrgChangeScenario(t *testing.T) {
	t.Parallel()

	// 模拟王磊从开发部换到生产部
	userAttribs := []*ldapv3.EntryAttribute{
		{Name: "objectClass", Values: []string{"inetOrgPerson"}},
		{Name: "cn", Values: []string{"王磊"}},
		{Name: "uid", Values: []string{"wanglei"}},
	}

	// 第一次登录：在开发部
	principal1, err := AttributesToPrincipal(
		userAttribs,
		"uid=wanglei,ou=dev,dc=example,dc=com",
		"openldap_user",
		"openldap",
		"inetOrgPerson",
		"cn",
		"uid",
		"groupOfNames",
		"cn",
	)
	require.NoError(t, err)

	// 第二次登录：换到生产部（DN 改变）
	principal2, err := AttributesToPrincipal(
		userAttribs,
		"uid=wanglei,ou=prod,dc=example,dc=com",
		"openldap_user",
		"openldap",
		"inetOrgPerson",
		"cn",
		"uid",
		"groupOfNames",
		"cn",
	)
	require.NoError(t, err)

	// 关键断言：两次登录生成的 principalName 应该相同
	assert.Equal(t, principal1.ObjectMeta.Name, principal2.ObjectMeta.Name,
		"principalName should remain the same when user moves between OUs")
	assert.Equal(t, "openldap_user://wanglei", principal1.ObjectMeta.Name,
		"principalName should use stable login attribute, not DN")
}

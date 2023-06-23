package formatter

func (c *idPWrapper) OIDCEnabled() bool {
	return c.Provider.GetOpenIdEnabled()
}

// AccessTokenTTL
func (c *idPWrapper) OIDCAccessTokenTTL() int32 {
	return c.Provider.GetOidcAccessTokenTimeToLive()
}

// AuthzCodeTTL
func (c *idPWrapper) OIDCAuthzCodeTTL() int32 {
	return c.Provider.GetOidcAuthzCodeTimeToLive()
}

// IDTokenTTL
func (c *idPWrapper) OIDCIDTokenTTL() int32 {
	return c.Provider.GetOidcIdTokenTimeToLive()
}

// User claims in access token (bool)
func (c *idPWrapper) OIDCUserClaimsInAccessToken() bool {
	return c.Provider.GetOidcIncludeUserClaimsInAccessToken()
}

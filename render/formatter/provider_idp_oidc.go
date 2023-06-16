package formatter

func (c *idPWrapper) OIDCEnabled() bool {
	return c.p.GetOpenIdEnabled()
}

// AccessTokenTTL
func (c *idPWrapper) OIDCAccessTokenTTL() int32 {
	return c.p.GetOidcAccessTokenTimeToLive()
}

// AuthzCodeTTL
func (c *idPWrapper) OIDCAuthzCodeTTL() int32 {
	return c.p.GetOidcAuthzCodeTimeToLive()
}

// IDTokenTTL
func (c *idPWrapper) OIDCIDTokenTTL() int32 {
	return c.p.GetOidcIdTokenTimeToLive()
}

// User claims in access token (bool)
func (c *idPWrapper) OIDCUserClaimsInAccessToken() bool {
	return c.p.GetOidcIncludeUserClaimsInAccessToken()
}

package formatter

func (c *idPWrapper) OAuth2Enabled() bool {
	return c.Provider.GetOauth2Enabled()
}

func (c *idPWrapper) OAuth2SharedKey() string {
	return c.Provider.GetOauth2Key()
}

func (c *idPWrapper) OAuth2TokenValidity() int64 {
	return c.Provider.GetOauth2TokenValidity()
}

func (c *idPWrapper) OAuth2RememberMeTokenValidity() int64 {
	return c.Provider.GetOauth2RememberMeTokenValidity()
}

func (c *idPWrapper) PwdlessAuthnEnabled() bool {
	return c.Provider.GetPwdlessAuthnEnabled()
}

func (c *idPWrapper) PwdlessAuthnSubject() string {
	return c.Provider.GetPwdlessAuthnSubject()
}

func (c *idPWrapper) PwdlessAuthnTemplate() string {
	return c.Provider.GetPwdlessAuthnTemplate()
}

func (c *idPWrapper) PwdlessAuthnTo() string {
	return c.Provider.GetPwdlessAuthnTo()
}

func (c *idPWrapper) PwdlessAuthnFrom() string {
	return c.Provider.GetPwdlessAuthnFrom()
}

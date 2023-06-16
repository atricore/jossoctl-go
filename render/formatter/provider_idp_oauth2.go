package formatter

func (c *idPWrapper) OAuth2Enabled() bool {
	return c.p.GetOauth2Enabled()
}

func (c *idPWrapper) OAuth2SharedKey() string {
	return c.p.GetOauth2Key()
}

func (c *idPWrapper) OAuth2TokenValidity() int64 {
	return c.p.GetOauth2TokenValidity()
}

func (c *idPWrapper) OAuth2RememberMeTokenValidity() int64 {
	return c.p.GetOauth2RememberMeTokenValidity()
}

func (c *idPWrapper) PwdlessAuthnEnabled() bool {
	return c.p.GetPwdlessAuthnEnabled()
}

func (c *idPWrapper) PwdlessAuthnSubject() string {
	return c.p.GetPwdlessAuthnSubject()
}

func (c *idPWrapper) PwdlessAuthnTemplate() string {
	return c.p.GetPwdlessAuthnTemplate()
}

func (c *idPWrapper) PwdlessAuthnTo() string {
	return c.p.GetPwdlessAuthnTo()
}

func (c *idPWrapper) PwdlessAuthnFrom() string {
	return c.p.GetPwdlessAuthnFrom()
}

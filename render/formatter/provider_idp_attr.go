package formatter

import api "github.com/atricore/josso-api-go"

type amWrapper struct {
	am *api.AttributeMappingDTO
}

func (c *amWrapper) AttrName() string {
	return c.am.GetAttrName()
}

func (c *amWrapper) ReportedAttrName() string {
	return c.am.GetReportedAttrName()
}

func (c *amWrapper) ReportedAttrNameFormat() string {
	return c.am.GetReportedAttrNameFormat()
}

func (c *amWrapper) Type() string {
	return c.am.GetType()
}

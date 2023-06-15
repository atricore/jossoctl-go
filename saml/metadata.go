package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
)

type KeyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use     string   `xml:"use,attr"`
	KeyInfo KeyInfo  `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data
}

type X509Data struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	Cert    X509Certificate
}

type X509Certificate struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Certificate string   `xml:",innerxml"`
}

type EntityDescriptor struct {
	XMLName    xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID   string           `xml:"entityID,attr"`
	SpSsoDesc  SPSSODescriptor  `xml:"SPSSODescriptor"`
	IdpSsoDesc IDPSSODescriptor `xml:"IDPSSODescriptor"`
}

type AssertionConsumerService struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	Location         string   `xml:"Location,attr"`
	ResponseLocation string   `xml:"ResponseLocation,attr"`
	Binding          string   `xml:"Binding,attr"`
}

type SingleLogoutService struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	Location         string   `xml:"Location,attr"`
	ResponseLocation string   `xml:"ResponseLocation,attr"`
	Binding          string   `xml:"Binding,attr"`
}

type SPSSODescriptor struct {
	XMLName     xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	KeyDescList []KeyDescriptor            `xml:"KeyDescriptor"`
	ACServices  []AssertionConsumerService `xml:"AssertionConsumerService"`
	SLServices  []SingleLogoutService      `xml:"SingleLogoutService"`
}

type IDPSSODescriptor struct {
	XMLName     xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	KeyDescList []KeyDescriptor       `xml:"KeyDescriptor"`
	SSOServices []SingleSignOnService `xml:"SingleSignOnService"`
	SLServices  []SingleLogoutService `xml:"SingleLogoutService"`
}

type SingleSignOnService struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Location         string   `xml:"Location,attr"`
	ResponseLocation string   `xml:"ResponseLocation,attr"`
	Binding          string   `xml:"Binding,attr"`
}

type SAMLEndpoint struct {
	URL         string
	ResponseURL string
	Binding     string
	Type        string
}

func GetEntityDescriptor(b64Metadata string) (*EntityDescriptor, error) {

	decodedData, err := base64.StdEncoding.DecodeString(b64Metadata)
	if err != nil {
		return nil, err
	}

	var descriptor EntityDescriptor
	err = xml.Unmarshal(decodedData, &descriptor)
	if err != nil {
		return nil, err
	}

	return &descriptor, nil

}

func GetProviderCertificatesFromStr(b64Metadata string) (*x509.Certificate, *x509.Certificate, error) {
	descriptor, err := GetEntityDescriptor(b64Metadata)
	if err != nil {
		return nil, nil, err
	}
	return GetProviderCertificates(descriptor)
}

func GetProviderCertificates(descriptor *EntityDescriptor) (*x509.Certificate, *x509.Certificate, error) {

	var signingCert, encryptionCert *x509.Certificate

	// handle SP case
	for _, keyDescriptor := range descriptor.SpSsoDesc.KeyDescList {
		certData, err := base64.StdEncoding.DecodeString(keyDescriptor.KeyInfo.X509Data.Cert.Certificate)
		if err != nil {
			return nil, nil, err
		}

		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, nil, err
		}

		if keyDescriptor.Use == "signing" {
			signingCert = cert
		} else if keyDescriptor.Use == "encryption" {
			encryptionCert = cert
		}
	}

	// handle IDP case
	for _, keyDescriptor := range descriptor.IdpSsoDesc.KeyDescList {
		certData, err := base64.StdEncoding.DecodeString(keyDescriptor.KeyInfo.X509Data.Cert.Certificate)
		if err != nil {
			return nil, nil, err
		}

		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, nil, err
		}

		if keyDescriptor.Use == "signing" {
			signingCert = cert
		} else if keyDescriptor.Use == "encryption" {
			encryptionCert = cert
		}
	}

	return signingCert, encryptionCert, nil
}

func GetSPEndpointsFromStr(b64Metadata string) ([]SAMLEndpoint, error) {
	descriptor, err := GetEntityDescriptor(b64Metadata)
	if err != nil {
		return nil, err
	}
	return GetSPEndpoints(descriptor)
}

func GetSPEndpoints(descriptor *EntityDescriptor) ([]SAMLEndpoint, error) {
	var endpoints []SAMLEndpoint

	// Extract the AssertionConsumerService endpoints
	for _, acs := range descriptor.SpSsoDesc.ACServices {
		endpoints = append(endpoints, SAMLEndpoint{
			URL:         acs.Location,
			ResponseURL: acs.ResponseLocation,
			Binding:     acs.Binding,
			Type:        "AssertionConsumerService",
		})
	}

	// Extract the SingleLogoutService endpoints
	for _, sls := range descriptor.SpSsoDesc.SLServices {
		endpoints = append(endpoints, SAMLEndpoint{
			URL:         sls.Location,
			ResponseURL: sls.ResponseLocation,
			Binding:     sls.Binding,
			Type:        "SingleLogoutService",
		})
	}

	return endpoints, nil
}

func GetIDPEndpointsFromStr(b64Metadata string) ([]SAMLEndpoint, error) {
	descriptor, err := GetEntityDescriptor(b64Metadata)
	if err != nil {
		return nil, err
	}

	return GetIDPEndpoints(descriptor)
}

func GetIDPEndpoints(descriptor *EntityDescriptor) ([]SAMLEndpoint, error) {

	var endpoints []SAMLEndpoint

	// Extract the SingleSignOnService endpoints
	for _, sso := range descriptor.IdpSsoDesc.SSOServices {
		endpoints = append(endpoints, SAMLEndpoint{
			URL:         sso.Location,
			ResponseURL: sso.ResponseLocation,
			Binding:     sso.Binding,
			Type:        "SingleSignOnService",
		})
	}

	// Extract the SingleLogoutService endpoints
	for _, sls := range descriptor.IdpSsoDesc.SLServices {
		endpoints = append(endpoints, SAMLEndpoint{
			URL:         sls.Location,
			ResponseURL: sls.ResponseLocation,
			Binding:     sls.Binding,
			Type:        "SingleLogoutService",
		})
	}

	return endpoints, nil
}

func GetEntityIDFromStr(b64Metadata string) (string, error) {
	descriptor, err := GetEntityDescriptor(b64Metadata)
	if err != nil {
		return "", err
	}
	return GetEntityID(descriptor), nil

}

func GetEntityID(descriptor *EntityDescriptor) string {
	return descriptor.EntityID
}

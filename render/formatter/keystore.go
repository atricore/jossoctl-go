package formatter

import (
	api "github.com/atricore/josso-api-go"
)

const (
	keystoreTFFormat = `{{- if .HasKeystore}}
	
	keystore {
		{{- if .HasCertificateAlias}}
		alias         = "{{.CertificateAlias}}"
		{{- end}}
		password      = "{{.KeystorePassword}}"
		{{- if .HasKeyPassword}}
		key_password  = "{{.KeyPassword}}"
		{{- end}}
		resource      = "{{.KeystoreResource}}"
	}
	{{- end}}
	`

	keystoreFormat = `    Keystore
	Certificate Alias: {{.CertificateAlias}}
	Key Alias: {{.KeyAlias}}
   
	Version:       {{.Version}}
	Serial Number: {{.SerialNumber}}
	Issuer:        {{.Issuer}}
	Subjects:      {{.Subjects}}
	Not Before:    {{.NotBefore}}
	Not After:     {{.NotAfter}}
   
	Certificate:                
   {{.Certificate}} `
)

type KeystoreWrapper struct {
	Keystore *api.KeystoreDTO
}

func (w *KeystoreWrapper) TF() string {
	return "asf"
}

package util

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// writeToFile
func WriteToFile(out string, cfg string, replace bool) error {
	if _, err := os.Stat(out); err == nil {
		if replace {
			err := os.Remove(out)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("file %s already exists", out)
		}
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(cfg)
	if err != nil {
		return err
	}

	return nil
}

func CertificateToPEM(cert *x509.Certificate) (string, error) {
	encodeCert := base64.StdEncoding.EncodeToString([]byte(cert.RawTBSCertificate))
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte(encodeCert),
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, block); err != nil {
		return "", err
	}

	return fmt.Sprint(buf), nil
}

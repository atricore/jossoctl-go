package util

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// readFromFile
func ReadFromFile(in string) (string, error) {
	f, err := os.Open(in)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// read from f
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(f)
	if err != nil {
		return "", err
	}
	content := buf.String()
	return content, nil
}

// writeToFile
func WriteToFile(out string, content string, replace bool) error {
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

	_, err = f.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func WriteBytesToFile(out string, content []byte, replace bool) error {
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

	_, err = f.Write(content)
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

func AskUser() bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		s, _ := reader.ReadString('\n')
		s = strings.TrimSuffix(s, "\n")
		s = strings.ToLower(s)
		if len(s) > 1 {
			fmt.Println("Please enter Y or N")
			continue
		}
		if strings.Compare(s, "n") == 0 || strings.Compare(s, "") == 0 {
			return false
		} else if strings.Compare(s, "y") == 0 {
			break
		} else {
			continue
		}
	}
	return true
}

package util

import (
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

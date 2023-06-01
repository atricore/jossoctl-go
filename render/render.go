package render

import (
	"io"
	"os"
)

func RenderToFile(r func(out io.Writer), fName string, replace bool) error {

	flags := os.O_RDWR | os.O_CREATE | os.O_EXCL
	if replace {
		flags = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	}

	// Open the file with the appropriate flags.
	// This will fail if replace is false and the file already exists.
	file, err := os.OpenFile(fName, flags, 0755)
	if err != nil {
		return err
	}

	defer file.Close()

	r(file)

	return nil

}

package formatter

import (
	"strings"
)

func TruncateID(id string, shortLen int) string {
	if i := strings.IndexRune(id, ':'); i >= 0 {
		id = id[i+1:]
	}
	if len(id) > shortLen {
		id = id[:shortLen]
	}
	return id
}

// LeftPad adds padding to the left of the string.
func LeftPad(str, pad string, length int) string {
	for {
		str = pad + str
		if len(str) >= length {
			return str[0:length]
		}
	}
}

// RightPad adds padding to the right of the string.
func RightPad(str, pad string, length int) string {
	for {
		str = str + pad
		if len(str) >= length {
			return str[0:length]
		}
	}
}

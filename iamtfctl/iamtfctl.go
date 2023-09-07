/*
Copyright © 2022 Sebastian Gonzalez Oyuela sgonzalez@atricore.com
*/
package main

import (
	"github.com/atricore/josso-cli-go/cmd"
)

var (
	version string
)

func main() {
	cmd.VERSION = version
	cmd.ExecuteIamtf()
}

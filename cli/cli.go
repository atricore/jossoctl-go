package cli

import (
	"fmt"
	"io"
	"os"

	sdk "github.com/atricore/josso-sdk-go"
	"github.com/spf13/viper"
)

type JossoCli struct {
	cfg *sdk.IdbusServer
	cli *sdk.IdbusApiClient
}

type Cli interface {
	Client() *sdk.IdbusApiClient
	Out() io.Writer
	Error(err error)
	// Out() *streams.Out
}

func (c JossoCli) Client() *sdk.IdbusApiClient {
	return c.cli
}

func (c JossoCli) Out() io.Writer {
	return os.Stdout
}

func (c JossoCli) Error(err error) {
	fmt.Fprintf(c.Out(), "%s\n", err)
}

func CreateClient(server *sdk.IdbusServer) (Cli, error) {

	var err error
	var cli Cli

	l := sdk.NewDefaultLogger(viper.GetBool("debug"))
	c := sdk.NewIdbusApiClient(&l, viper.GetBool("trace"))
	err = c.RegisterServer(server, "")
	if err != nil {
		return cli, fmt.Errorf("cannot create client: %v", err)
	}

	err = c.Authn()
	if err != nil {
		return cli, fmt.Errorf("cannot authenticate client: %v", err)
	}

	return JossoCli{
		cli: c,
		cfg: server,
	}, err

}

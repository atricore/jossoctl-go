module github.com/atricore/josso-cli-go

go 1.16

replace github.com/atricore/josso-api-go => ../josso-api-go

replace github.com/atricore/josso-sdk-go => ../josso-sdk-go

require (
	github.com/atricore/josso-api-go v0.0.0-20220526195012-e4e56208f6c9
	github.com/atricore/josso-sdk-go v0.0.0-20220526195150-5ddec793f1d8
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.4.0
	github.com/spf13/viper v1.10.1
)

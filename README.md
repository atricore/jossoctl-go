# jossoctl

Command line interface tools for managing JOSSO EE and IAM.tf identity appliances.

## Installation

Download the latest release for your platform from the [releases page](https://github.com/atricore/josso-cli-go/releases).

Extract the archive and add the binary to your PATH:

```bash
# Example for Linux/macOS
unzip jossoctl_<version>_<os>_<arch>.zip
chmod +x jossoctl_v*
sudo mv jossoctl_v* /usr/local/bin/jossoctl
```

## Quick Start

### Authentication

Configure authentication using environment variables with the `JOSSO_API_` prefix:

```bash
export JOSSO_API_ENDPOINT="https://your-server.com/atricore-rest/services"
export JOSSO_API_CLIENT_ID="your-client-id"
export JOSSO_API_SECRET="your-client-secret"
```

Or use command-line flags:

```bash
jossoctl --endpoint "https://your-server.com/atricore-rest/services" \
         --client-id "your-client-id" \
         --client-secret "your-client-secret" \
         list appliances
```

### Configuration File

Alternatively, create a config file at `~/.iamtf/iamtf.yaml`:

```yaml
endpoint: https://your-server.com/atricore-rest/services
client_id: your-client-id
secret: your-client-secret
```

## Common Commands

### List Resources

```bash
# List all appliances
jossoctl list appliances

# List identity sources
jossoctl list idsources -a <appliance-name>

# List providers
jossoctl list providers -a <appliance-name>

# List brandings
jossoctl list brandings -a <appliance-name>
```

### View Resource Details

```bash
# View appliance details
jossoctl view appliance <appliance-name>

# View identity source details
jossoctl view idsource <idsource-name> -a <appliance-name>

# View provider details
jossoctl view provider <provider-name> -a <appliance-name>
```

### Manage Appliances

```bash
# Start an appliance
jossoctl start -a <appliance-name>

# Stop an appliance
jossoctl stop -a <appliance-name>

# Validate appliance configuration
jossoctl validate -a <appliance-name>

# Layout appliance (deploy configuration)
jossoctl layout -a <appliance-name>

# Activate execution environments
jossoctl activate -a <appliance-name>
```

### Export & Import

```bash
# Export appliance configuration
jossoctl export appliance <appliance-name> > appliance.json

# Import appliance configuration
jossoctl import appliance -f appliance.json

# Export provider metadata
jossoctl export provider-metadata <provider-name> -a <appliance-name>

# Export provider certificate
jossoctl export provider-cert <provider-name> -a <appliance-name>
```

### Generate Terraform Resources

```bash
# Generate Terraform configuration for appliance
jossoctl generate-tf appliance <appliance-name>

# Generate Terraform configuration for provider
jossoctl generate-tf provider <provider-name> -a <appliance-name>

# Generate Terraform configuration for identity source
jossoctl generate-tf idsource <idsource-name> -a <appliance-name>
```

### Server Information

```bash
# Get server version
jossoctl server info

# List available server bundles
jossoctl server bundles
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JOSSO_API_ENDPOINT` | JOSSO/IAM.tf server endpoint | `http://localhost:8081/atricore-rest/services` |
| `JOSSO_API_CLIENT_ID` | OAuth2 client ID | - |
| `JOSSO_API_SECRET` | OAuth2 client secret | - |
| `JOSSO_API_APPLIANCE` | Default appliance name | - |
| `JOSSO_API_DEBUG` | Enable debug mode | `false` |
| `JOSSO_API_TRACE` | Enable API traffic tracing | `false` |
| `JOSSO_API_QUIET` | Suppress output | `false` |

## Global Flags

```
  -a, --appliance string         Appliance id or name
      --client-id string         OAuth2 client id
      --client-password string   User password for authentication
      --client-secret string     OAuth2 client secret
      --client-user string       Username for authentication
      --config string            Config file path
  -d, --debug                    Enable client debug mode
  -e, --endpoint string          Server endpoint URL
  -h, --help                     Show help information
      --quiet                    Suppress output
      --trace                    Trace API traffic
  -v, --verbose                  Verbose output
```

## Examples

### Complete Workflow

```bash
# Set authentication
export JOSSO_API_ENDPOINT="https://iam.example.com/atricore-rest/services"
export JOSSO_API_CLIENT_ID="my-client"
export JOSSO_API_SECRET="my-secret"

# List all appliances
jossoctl list appliances

# Set default appliance
export JOSSO_API_APPLIANCE="my-appliance"

# View appliance configuration
jossoctl view appliance my-appliance

# Validate and deploy
jossoctl validate -a my-appliance
jossoctl layout -a my-appliance
jossoctl activate -a my-appliance

# Start the appliance
jossoctl start -a my-appliance
```

## License

See [LICENSE.md](LICENSE.md)

## Support

For issues and questions, please visit the [issue tracker](https://github.com/atricore/josso-cli-go/issues).

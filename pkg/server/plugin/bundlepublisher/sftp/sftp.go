package sftp

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/pkg/sftp"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher/common"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName = "sftp"
)

// BuiltIn returns a new BundlePublisher built-in plugin.
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

// New creates a new sftp BundlePublisher plugin instance.
func New() *Plugin {
	return &Plugin{
		log: hclog.NewNullLogger(),
	}
}

// Config holds the configuration of the plugin.
type Config struct {
	Host        string `hcl:"host" json:"host"`
	Port        int    `hcl:"port" json:"port"`
	User        string `hcl:"user" json:"user"`
	Password    string `hcl:"password" json:"password"`
	PrivateKey  string `hcl:"private_key" json:"private_key"`
	FilePath    string `hcl:"file_path" json:"file_path"`
	Format      string `hcl:"format" json:"format"`
	RefreshHint string `hcl:"refresh_hint" json:"refresh_hint"`
	FileMode    string `hcl:"file_mode" json:"file_mode"`

	// bundleFormat is used to store the content of Format, parsed
	// as bundleformat.Format.
	bundleFormat bundleformat.Format

	// parsedRefreshHint is used to store the content of RefreshHint, parsed
	// as an int64.
	parsedRefreshHint int64

	// parsedFileMode is used to store the content of FileMode, parsed
	// as os.FileMode.
	parsedFileMode os.FileMode
}

// buildConfig builds the plugin configuration from the provided HCL config.
func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	// Required fields
	if newConfig.Host == "" {
		status.ReportError("configuration is missing the host")
	}

	if newConfig.User == "" {
		status.ReportError("configuration is missing the user")
	}

	// Authentication: require either password or private key
	if newConfig.Password == "" && newConfig.PrivateKey == "" {
		status.ReportError("configuration must provide either password or private_key for authentication")
	}

	if newConfig.FilePath == "" {
		status.ReportError("configuration is missing the file path")
	}

	if newConfig.Format == "" {
		status.ReportError("configuration is missing the bundle format")
	}

	// Default port
	if newConfig.Port == 0 {
		newConfig.Port = 22
	}

	bundleFormat, err := bundleformat.FromString(newConfig.Format)
	if err != nil {
		status.ReportErrorf("could not parse bundle format from configuration: %v", err)
	} else {
		// This plugin supports JWKS, SPIFFE, and PEM formats
		switch bundleFormat {
		case bundleformat.JWKS:
		case bundleformat.SPIFFE:
		case bundleformat.PEM:
		default:
			status.ReportErrorf("bundle format %q is not supported", newConfig.Format)
		}
		newConfig.bundleFormat = bundleFormat
	}

	if newConfig.RefreshHint != "" {
		refreshHint, err := common.ParseRefreshHint(newConfig.RefreshHint, status)
		if err != nil {
			status.ReportErrorf("could not parse refresh_hint: %v", err)
		}
		newConfig.parsedRefreshHint = refreshHint
	}

	// Parse file mode (default to 0644 if not specified)
	if newConfig.FileMode != "" {
		var mode uint32
		_, err := fmt.Sscanf(newConfig.FileMode, "%o", &mode)
		if err != nil {
			status.ReportErrorf("could not parse file_mode: %v", err)
		} else {
			newConfig.parsedFileMode = os.FileMode(mode)
		}
	} else {
		newConfig.parsedFileMode = 0644
	}

	return newConfig
}

// Plugin is the main representation of this bundle publisher plugin.
type Plugin struct {
	bundlepublisherv1.UnsafeBundlePublisherServer
	configv1.UnsafeConfigServer

	config    *Config
	configMtx sync.RWMutex

	bundle    *types.Bundle
	bundleMtx sync.RWMutex

	log hclog.Logger
}

// SetLogger sets a logger in the plugin.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, notes, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}
	for _, note := range notes {
		p.log.Warn(note)
	}

	p.setConfig(newConfig)
	p.setBundle(nil)
	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the plugin configuration.
func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
}

// PublishBundle writes the bundle to the configured SFTP server.
func (p *Plugin) PublishBundle(ctx context.Context, req *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if req.Bundle == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bundle in request")
	}

	currentBundle := p.getBundle()
	if proto.Equal(req.Bundle, currentBundle) {
		// Bundle not changed. No need to publish.
		return &bundlepublisherv1.PublishBundleResponse{}, nil
	}

	bundleToPublish := proto.Clone(req.Bundle).(*types.Bundle)
	if config.parsedRefreshHint != 0 {
		bundleToPublish.RefreshHint = config.parsedRefreshHint
	}

	formatter := bundleformat.NewFormatter(bundleToPublish)
	bundleBytes, err := formatter.Format(config.bundleFormat)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not format bundle: %v", err)
	}

	// Upload to SFTP server
	if err := p.uploadToSFTP(config, bundleBytes); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to upload bundle to SFTP server: %v", err)
	}

	p.setBundle(req.Bundle)
	p.log.Debug("Bundle published", "host", config.Host, "path", config.FilePath, "format", config.Format)
	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

// uploadToSFTP uploads data to the SFTP server.
func (p *Plugin) uploadToSFTP(config *Config, data []byte) error {
	// Create SSH client config
	sshConfig := &ssh.ClientConfig{
		User:            config.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Add host key verification option
		Auth:            []ssh.AuthMethod{},
	}

	// Add authentication method
	if config.Password != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.Password(config.Password))
	}
	if config.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(config.PrivateKey))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	sshClient, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %w", err)
	}
	defer sshClient.Close()

	// Create SFTP client
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer sftpClient.Close()

	// Ensure directory exists
	dir := filepath.Dir(config.FilePath)
	if err := sftpClient.MkdirAll(dir); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write atomically: write to temp file, then rename
	tmpPath := config.FilePath + ".tmp"
	tmpFile, err := sftpClient.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	// Ensure cleanup on error
	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
			sftpClient.Remove(tmpPath)
		}
	}()

	// Write data
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Close before chmod/rename
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}
	tmpFile = nil

	// Set file mode
	if err := sftpClient.Chmod(tmpPath, config.parsedFileMode); err != nil {
		return fmt.Errorf("failed to set file mode: %w", err)
	}

	// Atomic rename
	if err := sftpClient.Rename(tmpPath, config.FilePath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// getBundle gets the latest bundle that the plugin has.
func (p *Plugin) getBundle() *types.Bundle {
	p.bundleMtx.RLock()
	defer p.bundleMtx.RUnlock()

	return p.bundle
}

// getConfig gets the configuration of the plugin.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// setBundle updates the current bundle in the plugin with the provided bundle.
func (p *Plugin) setBundle(bundle *types.Bundle) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()

	p.bundle = bundle
}

// setConfig sets the configuration for the plugin.
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()

	p.config = config
}

// builtin creates a new BundlePublisher built-in plugin.
func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		bundlepublisherv1.BundlePublisherPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Ensure the interface is implemented by verifying types at compile time.
var _ io.Closer = (*sftp.Client)(nil)
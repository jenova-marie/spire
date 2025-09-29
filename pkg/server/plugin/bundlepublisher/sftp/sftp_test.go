package sftp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testUser     = "testuser"
	testPassword = "testpass"
	testPort     = 2022
)

func TestConfigure(t *testing.T) {
	// Generate test SSH key
	privateKey, err := generateTestKey()
	require.NoError(t, err)

	for _, tt := range []struct {
		name       string
		config     *Config
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "success with password auth",
			config: &Config{
				Host:     "localhost",
				Port:     testPort,
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "spiffe",
			},
		},
		{
			name: "success with private key auth",
			config: &Config{
				Host:       "localhost",
				Port:       testPort,
				User:       testUser,
				PrivateKey: privateKey,
				FilePath:   "/tmp/bundle.json",
				Format:     "spiffe",
			},
		},
		{
			name: "success with JWKS format",
			config: &Config{
				Host:     "localhost",
				Port:     testPort,
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.jwks",
				Format:   "jwks",
			},
		},
		{
			name: "success with PEM format",
			config: &Config{
				Host:     "localhost",
				Port:     testPort,
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.pem",
				Format:   "pem",
			},
		},
		{
			name: "success with refresh hint",
			config: &Config{
				Host:        "localhost",
				Port:        testPort,
				User:        testUser,
				Password:    testPassword,
				FilePath:    "/tmp/bundle.json",
				Format:      "spiffe",
				RefreshHint: "1h",
			},
		},
		{
			name: "success with custom file mode",
			config: &Config{
				Host:     "localhost",
				Port:     testPort,
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "spiffe",
				FileMode: "0600",
			},
		},
		{
			name: "no host",
			config: &Config{
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the host",
		},
		{
			name: "no user",
			config: &Config{
				Host:     "localhost",
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the user",
		},
		{
			name: "no authentication",
			config: &Config{
				Host:     "localhost",
				User:     testUser,
				FilePath: "/tmp/bundle.json",
				Format:   "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration must provide either password or private_key for authentication",
		},
		{
			name: "no file path",
			config: &Config{
				Host:     "localhost",
				User:     testUser,
				Password: testPassword,
				Format:   "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the file path",
		},
		{
			name: "no format",
			config: &Config{
				Host:     "localhost",
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the bundle format",
		},
		{
			name: "invalid format",
			config: &Config{
				Host:     "localhost",
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "invalid",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse bundle format",
		},
		{
			name: "unsupported format",
			config: &Config{
				Host:     "localhost",
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "der",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse bundle format",
		},
		{
			name: "invalid refresh hint",
			config: &Config{
				Host:        "localhost",
				User:        testUser,
				Password:    testPassword,
				FilePath:    "/tmp/bundle.json",
				Format:      "spiffe",
				RefreshHint: "invalid",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse refresh_hint",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			resp, err := doConfigure(t, p, tt.config)

			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Empty(t, resp)
		})
	}
}

func TestValidate(t *testing.T) {
	for _, tt := range []struct {
		name       string
		config     *Config
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "success",
			config: &Config{
				Host:     "localhost",
				Port:     testPort,
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "spiffe",
			},
		},
		{
			name: "missing host",
			config: &Config{
				User:     testUser,
				Password: testPassword,
				FilePath: "/tmp/bundle.json",
				Format:   "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the host",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			resp, err := doValidate(t, p, tt.config)

			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.Valid)
		})
	}
}

func TestPublishBundle(t *testing.T) {
	// Skip SFTP server tests - these require a running SFTP server
	t.Skip("SFTP integration tests require a running SFTP server")

	bundle := makeBundle(t)

	for _, tt := range []struct {
		name       string
		config     *Config
		bundle     *types.Bundle
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name:       "not configured",
			bundle:     bundle,
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
		{
			name: "missing bundle",
			config: &Config{
				Host:     "localhost",
				Port:     testPort,
				User:     testUser,
				Password: testPassword,
				FilePath: "/upload/missing-bundle.json",
				Format:   "spiffe",
			},
			bundle:     nil,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()

			if tt.config != nil {
				_, err := doConfigure(t, p, tt.config)
				require.NoError(t, err)
			}

			resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: tt.bundle,
			})

			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestPublishBundleIdempotency(t *testing.T) {
	t.Skip("SFTP integration tests require a running SFTP server")
}

func TestPublishBundleUpdate(t *testing.T) {
	t.Skip("SFTP integration tests require a running SFTP server")
}

// Helper functions

func doConfigure(t *testing.T, p *Plugin, config *Config) (*configv1.ConfigureResponse, error) {
	req := &configv1.ConfigureRequest{
		HclConfiguration: makeConfigHCL(config),
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "example.org",
		},
	}
	return p.Configure(context.Background(), req)
}

func doValidate(t *testing.T, p *Plugin, config *Config) (*configv1.ValidateResponse, error) {
	req := &configv1.ValidateRequest{
		HclConfiguration: makeConfigHCL(config),
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "example.org",
		},
	}
	return p.Validate(context.Background(), req)
}

func makeConfigHCL(config *Config) string {
	if config == nil {
		return ""
	}

	hcl := ""
	if config.Host != "" {
		hcl += `host = "` + config.Host + `"` + "\n"
	}
	if config.Port != 0 {
		hcl += fmt.Sprintf("port = %d\n", config.Port)
	}
	if config.User != "" {
		hcl += `user = "` + config.User + `"` + "\n"
	}
	if config.Password != "" {
		hcl += `password = "` + config.Password + `"` + "\n"
	}
	if config.PrivateKey != "" {
		hcl += "private_key = <<EOF\n" + config.PrivateKey + "EOF\n"
	}
	if config.FilePath != "" {
		hcl += `file_path = "` + config.FilePath + `"` + "\n"
	}
	if config.Format != "" {
		hcl += `format = "` + config.Format + `"` + "\n"
	}
	if config.RefreshHint != "" {
		hcl += `refresh_hint = "` + config.RefreshHint + `"` + "\n"
	}
	if config.FileMode != "" {
		hcl += `file_mode = "` + config.FileMode + `"` + "\n"
	}
	return hcl
}

func makeBundle(t *testing.T) *types.Bundle {
	return makeBundleWithSequence(t, 1)
}

func makeBundleWithSequence(t *testing.T, seq int) *types.Bundle {
	cert, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	// Modify serial number to make bundles distinguishable
	cert.SerialNumber.SetInt64(int64(seq))

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: uint64(seq),
	}
}

func generateTestKey() (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}
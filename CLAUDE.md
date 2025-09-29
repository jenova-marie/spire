# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

SPIRE (the SPIFFE Runtime Environment) is a production-grade implementation of the SPIFFE API specifications. It exposes the SPIFFE Workload API for workload attestation and issues SPIFFE IDs and SVIDs for establishing trust between software systems.

**Language**: Go 1.25.1
**Project Status**: CNCF Graduated Project

## Build Commands

### Core Build Tasks
```bash
make              # Build all SPIRE binaries (default)
make all          # Build, lint, and run unit tests
make build        # Builds all binaries after running tidy
```

### Building Individual Components
```bash
make bin/spire-server                # Build SPIRE Server
make bin/spire-agent                 # Build SPIRE Agent
make bin/oidc-discovery-provider     # Build OIDC Discovery Provider
```

### Testing
```bash
make test                            # Run unit tests (90s timeout unless NIGHTLY is set)
make race-test                       # Run unit tests with race detection

# Integration tests (requires Docker images)
make integration                     # Run integration tests
make integration SUITES='suites/join-token suites/k8s'  # Run specific suites
make integration IGNORE_SUITES='suites/flaky-test'      # Ignore specific suites
make integration-windows             # Run Windows-specific integration tests

# Single integration test
./test/integration/test-one.sh suites/<suite-name>
```

### Linting and Code Quality
```bash
make lint          # Run all linters (code + markdown)
make lint-code     # Lint Go code using golangci-lint
make lint-md       # Lint markdown files
make tidy          # Run go mod tidy
make tidy-check    # Verify repository is clean after tidy
```

### Code Generation
```bash
make generate           # Generate protobuf and plugin interface code
make generate-check     # Verify generated code is up to date
```

### Docker Images
```bash
make images                              # Build all Docker images (loads into local registry)
make images-no-load                      # Build without loading into local registry
make spire-server-image                  # Build SPIRE Server image only
make spire-agent-image                   # Build SPIRE Agent image only
make oidc-discovery-provider-image       # Build OIDC Discovery Provider image
make load-images                         # Load previously built images

# Windows images
make images-windows
make spire-server-image-windows
make spire-agent-image-windows
```

### Development Docker Environment
```bash
make dev-image     # Build development Docker image
make dev-shell     # Run shell in development container (shares .build cache and $GOPATH/pkg/mod)
```

## Architecture

### High-Level Structure

SPIRE follows a client-server architecture:

- **SPIRE Server**: Central authority that manages identities, performs attestation, and issues SVIDs
- **SPIRE Agent**: Runs on each workload node, attests workloads and provides the Workload API
- **OIDC Discovery Provider**: Serves OIDC discovery documents and JWKS bundles

### Directory Layout

```
cmd/
├── spire-agent/         # Agent CLI implementation
└── spire-server/        # Server CLI implementation

pkg/
├── agent/               # Agent process logic and support packages
│   └── plugin/          # Agent plugin implementations
├── server/              # Server process logic and support packages
│   └── plugin/          # Server plugin implementations
│       ├── bundlepublisher/       # Publish trust bundles to external systems
│       ├── credentialcomposer/    # Compose SVID credentials
│       ├── keymanager/            # Manage server private keys
│       ├── nodeattestor/          # Server-side node attestation
│       ├── notifier/              # Event notification plugins
│       └── upstreamauthority/     # Integrate with upstream CAs
└── common/              # Shared functionality for agent, server, and plugins

proto/spire/             # Protocol buffer definitions
└── common/              # Common protobuf definitions

support/
└── oidc-discovery-provider/  # OIDC Discovery Provider implementation

test/
├── integration/         # Integration test suites (executed with Docker)
├── spiretest/          # Test utilities
├── grpctest/           # gRPC testing helpers
├── clitest/            # CLI testing utilities
└── testca/             # Test certificate authority utilities
```

### Plugin Architecture

SPIRE uses a highly extensible plugin system. Plugins are categorized by type and side (agent vs server):

**Agent Plugin Types:**
- **KeyManager**: Manages agent private keys (disk, memory)
- **NodeAttestor**: Attests agent identity to server (AWS, Azure, GCP, K8s, join tokens, etc.)
- **WorkloadAttestor**: Introspects workloads to generate selectors (Docker, K8s, Unix, systemd, Windows)
- **SVIDStore**: Stores SVIDs in external systems (AWS Secrets Manager, GCP Secret Manager)

**Server Plugin Types:**
- **KeyManager**: Manages server private keys (disk, memory, AWS KMS, Azure Key Vault, GCP KMS)
- **NodeAttestor**: Server-side node attestation validation
- **UpstreamAuthority**: Integrates with upstream CAs (AWS ACM PCA, Vault, EJBCA, Cert-Manager, etc.)
- **BundlePublisher**: Publishes trust bundles (AWS S3, GCP Cloud Storage, K8s ConfigMap, AWS Roles Anywhere)
- **Notifier**: Event notifications (K8s bundle updates, GCS bundle updates)
- **CredentialComposer**: Composes SVID credentials (unique ID composer)

Each plugin type has standardized interfaces defined via protobuf in the `spire-plugin-sdk`.

### Core Data Flow

1. **Node Attestation**: Agent proves its identity to Server using a NodeAttestor plugin
2. **Workload Attestation**: Agent uses WorkloadAttestor plugins to identify workloads
3. **Registration**: Server matches workload attestation to registration entries (defines SPIFFE IDs)
4. **SVID Issuance**: Server issues SVIDs (X.509 or JWT) to entitled workloads via Agent
5. **Workload API**: Workloads retrieve SVIDs and trust bundles via Unix domain socket

### Code Generation

The codebase uses protobuf for:
- gRPC service definitions
- Plugin interfaces (via `protoc-gen-go-spire`)
- Common data structures

When modifying `.proto` files, always run `make generate` and verify with `make generate-check`.

## Development Conventions

### SQL Plugin Changes
Datastore schema changes must be present in at least one full minor release cycle before introducing code that depends on them. This ensures upgrade compatibility.

### Testing Strategy
- Unit tests: Cover individual package functionality
- Integration tests: Full end-to-end scenarios with Docker containers
- Integration test suites are under `test/integration/suites/`
- Each suite has numbered step scripts (`00-*`, `01-*`, etc.) and a mandatory `teardown` script

### Build System
- The Makefile automatically downloads and manages the Go toolchain in `.build/`
- Protoc, golangci-lint, and other tools are version-pinned in `.spire-tool-versions`
- Git version information is embedded in binaries via ldflags when the repository is clean

### Integration Testing
Integration tests:
- Run in isolated Docker containers
- Use the framework in `test/integration/`
- Each suite has a `README.md` describing what it tests
- Step scripts are sourced with `set -e -o pipefail`
- Common functions available from `test/integration/common`
- Environment variables: `REPODIR` (repo root), `ROOTDIR` (integration test dir)

## Important Notes

- This is a security-critical project; changes affecting trust, attestation, or SVID issuance require careful review
- The codebase follows SPIFFE specifications; consult https://github.com/spiffe/spiffe for standards
- Docker is required for integration tests and image builds
- Platform support: Linux, macOS, Windows (with platform-specific code in `_posix.go` and `_windows.go` files)
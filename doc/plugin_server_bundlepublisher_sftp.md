# Server plugin: BundlePublisher "sftp"

The `sftp` plugin publishes trust bundle contents to a remote SFTP server. This is useful for making the trust bundle available to remote systems, distributed applications, or integration with systems that support SFTP-based configuration distribution.

The plugin writes the bundle atomically (write to temporary file, then rename) to ensure that readers always see a consistent bundle state.

## Comparison with Other Bundle Publishers

| Feature                  | SFTP | AWS S3 | K8s ConfigMap |
|--------------------------|------|--------|---------------|
| Remote distribution      | ✓    | ✓      | ✓             |
| No cloud dependency      | ✓    | ✗      | ✗             |
| Atomic writes            | ✓    | ✗      | ✓             |
| Authentication required  | ✓    | ✓      | ✓             |
| Cross-platform           | ✓    | ✓      | ✗             |

## Configuration

| Configuration   | Description                                                                                                     | Default |
|-----------------|-----------------------------------------------------------------------------------------------------------------|---------|
| `host`          | Hostname or IP address of the SFTP server. **Required**                                                        |         |
| `port`          | Port number of the SFTP server.                                                                                 | `22`    |
| `user`          | Username for SFTP authentication. **Required**                                                                  |         |
| `password`      | Password for authentication. Either `password` or `private_key` is **required**.                                |         |
| `private_key`   | SSH private key for authentication (PEM format). Either `password` or `private_key` is **required**.            |         |
| `file_path`     | Path on the remote server where the bundle will be written. **Required**                                        |         |
| `format`        | The format to use for the bundle. Must be one of `spiffe`, `jwks`, or `pem`. **Required**                      |         |
| `refresh_hint`  | Optional duration string (e.g., "5m", "1h") indicating how often clients should refresh the bundle.            |         |
| `file_mode`     | Optional file permission mode in octal format (e.g., "0644", "0600"). Default: "0644"                          | `0644`  |

## Supported Bundle Formats

- **spiffe**: SPIFFE bundle format (JSON document containing trust domain and keys)
- **jwks**: JSON Web Key Set format (RFC 7517)
- **pem**: PEM-encoded X.509 certificates

## Authentication

The plugin supports two authentication methods:

1. **Password Authentication**: Use the `password` configuration parameter
2. **Public Key Authentication**: Use the `private_key` configuration parameter with a PEM-encoded SSH private key

You must provide either `password` or `private_key` (or both).

## Sample Configuration

### Password Authentication

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "sftp.example.com"
        port = 22
        user = "spire"
        password = "secure-password"
        file_path = "/var/spire/bundle/bundle.json"
        format = "spiffe"
    }
}
```

### Public Key Authentication

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "sftp.example.com"
        user = "spire"
        private_key = <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
...
-----END OPENSSH PRIVATE KEY-----
EOF
        file_path = "/var/spire/bundle/bundle.json"
        format = "spiffe"
    }
}
```

### Full Configuration with All Options

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "sftp.example.com"
        port = 2222
        user = "spire"
        password = "secure-password"
        file_path = "/opt/spire/bundles/bundle.jwks"
        format = "jwks"
        refresh_hint = "5m"
        file_mode = "0640"
    }
}
```

### Multiple Remote Servers

You can configure multiple SFTP publishers to distribute the bundle to different servers:

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "primary-sftp.example.com"
        user = "spire"
        password = "password1"
        file_path = "/bundles/bundle.json"
        format = "spiffe"
    }
}

BundlePublisher "sftp" {
    plugin_data {
        host = "backup-sftp.example.com"
        user = "spire"
        password = "password2"
        file_path = "/bundles/bundle.json"
        format = "spiffe"
    }
}
```

### Multiple Formats to Same Server

You can publish different formats to the same server:

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "sftp.example.com"
        user = "spire"
        password = "secure-password"
        file_path = "/bundles/bundle.json"
        format = "spiffe"
    }
}

BundlePublisher "sftp" {
    plugin_data {
        host = "sftp.example.com"
        user = "spire"
        password = "secure-password"
        file_path = "/bundles/bundle.jwks"
        format = "jwks"
    }
}

BundlePublisher "sftp" {
    plugin_data {
        host = "sftp.example.com"
        user = "spire"
        password = "secure-password"
        file_path = "/bundles/bundle.pem"
        format = "pem"
    }
}
```

## How It Works

1. The plugin is invoked automatically by the SPIRE Server when the trust bundle is updated
2. The plugin checks if the bundle has changed since the last publish (to avoid unnecessary uploads)
3. If changed, the bundle is formatted according to the configured format
4. The plugin connects to the SFTP server using SSH
5. The formatted bundle is written atomically:
   - Connect to SFTP server
   - Ensure the target directory exists
   - Write to a temporary file (`.tmp` suffix)
   - Set the configured file mode
   - Atomically rename to the target path
6. The atomic write ensures that readers never see a partially-written bundle

## Use Cases

### Distributed Application Configuration

Publish bundles to SFTP servers that serve as central configuration distribution points:

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "config-server.example.com"
        user = "spire"
        private_key = "..."
        file_path = "/config/trust/bundle.pem"
        format = "pem"
        refresh_hint = "5m"
    }
}
```

### Multi-Region Bundle Distribution

Distribute bundles to SFTP servers in different regions:

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "us-east-sftp.example.com"
        user = "spire"
        password = "..."
        file_path = "/bundles/bundle.json"
        format = "spiffe"
    }
}

BundlePublisher "sftp" {
    plugin_data {
        host = "eu-west-sftp.example.com"
        user = "spire"
        password = "..."
        file_path = "/bundles/bundle.json"
        format = "spiffe"
    }
}
```

### Legacy System Integration

Publish bundles to SFTP servers for systems that cannot directly integrate with SPIRE:

```hcl
BundlePublisher "sftp" {
    plugin_data {
        host = "legacy-sftp.example.com"
        user = "legacy-user"
        password = "legacy-password"
        file_path = "/certs/ca-bundle.pem"
        format = "pem"
        file_mode = "0444"
    }
}
```

## Security Considerations

- **Authentication**: Use SSH key-based authentication (`private_key`) instead of password authentication when possible for better security.
- **Host Key Verification**: The current implementation uses `InsecureIgnoreHostKey()` for host key verification. In production, you should verify host keys to prevent man-in-the-middle attacks.
- **File Permissions**: Use `file_mode` to restrict access to the bundle file. For sensitive environments, use `0600` or `0640`.
- **Network Security**: Ensure the SFTP connection is made over a secure network. Consider using VPN or private network connections.
- **Credentials Storage**: Store credentials securely. Consider using environment variables or secret management systems instead of hardcoding passwords in configuration files.
- **Directory Permissions**: Ensure the remote directory has appropriate permissions. The SFTP user must have write access to the target directory.

## Troubleshooting

### Error: "failed to connect to SSH server"

The plugin cannot establish a connection to the SFTP server.

**Solutions**:
1. Verify the `host` and `port` are correct
2. Ensure the SFTP server is running and accessible
3. Check firewall rules allow outbound connections from the SPIRE Server
4. Verify network connectivity with `telnet <host> <port>`

### Error: "password rejected"

Authentication with the provided credentials failed.

**Solutions**:
1. Verify the `user` and `password` are correct
2. Check if the user account is enabled on the SFTP server
3. Verify the user has permission to authenticate via password (some servers require key-based auth)

### Error: "failed to parse private key"

The provided private key is invalid or in an unsupported format.

**Solutions**:
1. Ensure the private key is in PEM format
2. Verify the key is not encrypted with a passphrase (passphrase-protected keys are not currently supported)
3. Check that the entire key including headers is included:
   ```
   -----BEGIN OPENSSH PRIVATE KEY-----
   ...
   -----END OPENSSH PRIVATE KEY-----
   ```

### Error: "failed to create directory"

The plugin cannot create the target directory on the SFTP server.

**Solutions**:
1. Verify the SFTP user has write permissions to the parent directory
2. Check if the parent directory exists
3. Manually create the directory on the SFTP server with appropriate permissions

### Error: "failed to rename file"

The atomic rename operation failed.

**Solutions**:
1. Verify the SFTP user has write permissions to the target directory
2. Check if a file with the same name exists and is locked by another process
3. Ensure sufficient disk space on the remote server

### Bundle Not Updating

If the bundle file is not being updated when the trust bundle changes:

1. Check SPIRE Server logs for errors from the SFTP bundle publisher
2. Verify the SFTP server is accessible and credentials are valid
3. Test SFTP connection manually with `sftp -P <port> <user>@<host>`
4. Ensure there is sufficient disk space on the remote server
5. Check that no other process has the file locked

## Performance Considerations

- The plugin performs atomic writes by writing to a temporary file and renaming, which is fast on most filesystems
- The plugin is idempotent: if the bundle hasn't changed, no SFTP upload occurs
- Multiple bundle publishers (even multiple SFTP publishers) run in parallel without blocking each other
- SSH connection establishment may take 1-2 seconds depending on network latency
- Consider using SSH connection multiplexing or persistent connections for better performance in high-frequency update scenarios

## Future Enhancements

Potential future improvements to this plugin:

1. **Host Key Verification**: Add support for verifying SFTP server host keys
2. **Connection Pooling**: Maintain persistent SFTP connections for better performance
3. **Passphrase Support**: Support for passphrase-protected private keys
4. **Certificate Authentication**: Support X.509 certificate-based SSH authentication
5. **Bandwidth Throttling**: Add options to limit upload bandwidth
6. **Retry Logic**: Implement automatic retry with exponential backoff for transient failures

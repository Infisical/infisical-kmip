# Infisical KMIP

[![Documentation](https://img.shields.io/badge/docs-online-blue)](https://infisical.com/docs/documentation/platform/kms/kmip)
[![Go Report Card](https://goreportcard.com/badge/github.com/infisical/infisical-kmip)](https://goreportcard.com/report/github.com/infisical/infisical-kmip)

Infisical KMIP is a fork of the [go-kmip](https://github.com/smira/go-kmip) project, extended to integrate with Infisical as a Key Management Service (KMS) for comprehensive key management and security solutions. It is designed to be used with KMIP clients, enabling seamless interaction with Infisical's KMS capabilities.

This package implements a subset of the [KMIP 1.4](http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html) protocol, including basic client/server operations. Additional operations and fields can be implemented by adding required Go structures with KMIP tags.

## Features

- **Infisical KMS Integration**: Extended to work with Infisical as a KMS, providing enhanced key management capabilities.
- **Full Key Management**: Implements key processing and management functionalities.

## Supported Operations

The server currently supports the following KMIP operations, primarily for symmetric keys:

- **Create**: Create symmetric keys.
- **Register**: Register symmetric keys.
- **Locate**: Locate keys based on attributes.
- **Get**: Retrieve symmetric keys.
- **Activate**: Activate keys.
- **Revoke**: Revoke keys.
- **Destroy**: Destroy keys.
- **Get Attributes**: Retrieve attributes of keys.
- **Query**: Query server capabilities and supported operations.

## Compatibility

- **Tested KMIP Versions**: The server has been tested for compatibility with KMIP versions 1.0 to 1.4.

## Recent Changes

- **Extension for Infisical KMS**: The fork has been extended to integrate with Infisical as a KMS, moving beyond the original encoding/decoding and base-level implementation.

## License

This code is licensed under [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

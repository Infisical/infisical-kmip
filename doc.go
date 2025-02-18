// Package kmip implements the KMIP protocol with extensions for Infisical KMS.
//
// Infisical KMIP is a fork of the go-kmip project, extended to integrate with
// Infisical as a Key Management Service (KMS) for comprehensive key management
// and security solutions. It is designed to be used with KMIP clients, enabling
// seamless interaction with Infisical's KMS capabilities.
//
// This package implements a subset of the KMIP 1.4 protocol, including basic
// client/server operations. Additional operations and fields can be implemented
// by adding required Go structures with KMIP tags.
//
// Features:
//   - Infisical KMS Integration: Extended to work with Infisical as a KMS, providing
//     enhanced key management capabilities.
//   - Full Key Management: Implements key processing and management functionalities.
//
// Supported Operations:
// The server currently supports the following KMIP operations, primarily for
// symmetric keys:
// - Create: Create symmetric keys.
// - Register: Register symmetric keys.
// - Locate: Locate keys based on attributes.
// - Get: Retrieve symmetric keys.
// - Activate: Activate keys.
// - Revoke: Revoke keys.
// - Destroy: Destroy keys.
// - Get Attributes: Retrieve attributes of keys.
// - Query: Query server capabilities and supported operations.
//
// Compatibility:
//   - Tested KMIP Versions: The server has been tested for compatibility with KMIP
//     versions 1.0 to 1.4.

package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

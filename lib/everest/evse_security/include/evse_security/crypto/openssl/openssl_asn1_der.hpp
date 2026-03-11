// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#pragma once

#ifdef USING_CUSTOM_PROVIDER

#include <cstdint>
#include <string>
#include <vector>

namespace evse_security {
namespace asn1 {

/// @brief Encode a length field in DER format (short or long form)
/// @param length The length to encode
/// @return Vector of bytes representing the encoded length
std::vector<uint8_t> encode_length(size_t length);

/// @brief Encode a VisibleString (ASN.1 tag 0x1a)
/// @param str The string to encode
/// @return Vector of bytes representing the encoded VisibleString
std::vector<uint8_t> encode_visible_string(const std::string& str);

/// @brief Encode a UTF8String (ASN.1 tag 0x0c)
/// @param str The string to encode
/// @return Vector of bytes representing the encoded UTF8String
std::vector<uint8_t> encode_utf8_string(const std::string& str);

/// @brief Encode a SEQUENCE (ASN.1 tag 0x30)
/// @param elements Vector of encoded elements to include in the sequence
/// @return Vector of bytes representing the encoded SEQUENCE
std::vector<uint8_t> encode_sequence(const std::vector<std::vector<uint8_t>>& elements);

/// @brief Encode a PKCS#11 URI in DER format
/// @param uri The PKCS#11 URI to encode
/// @return Vector of bytes representing the DER-encoded structure
///
/// The structure is:
/// SEQUENCE {
///     VisibleString: "PKCS#11 Provider URI v1.0"
///     UTF8String: uri
/// }
std::vector<uint8_t> encode_pkcs11_uri_der(const std::string& uri);

/// @brief Convert DER-encoded data to PEM format
/// @param der The DER-encoded data
/// @param label The PEM label (e.g., "PKCS#11 PROVIDER URI")
/// @return String containing the PEM-formatted data with armor
std::string der_to_pem(const std::vector<uint8_t>& der, const std::string& label);

} // namespace asn1
} // namespace evse_security

#endif // USING_CUSTOM_PROVIDER

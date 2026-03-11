// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include <evse_security/crypto/openssl/openssl_asn1_der.hpp>

#ifdef USING_CUSTOM_PROVIDER

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <everest/logging.hpp>

namespace evse_security {
namespace asn1 {

std::vector<uint8_t> encode_length(size_t length) {
    std::vector<uint8_t> result;

    if (length < 128) {
        // Short form: one byte
        result.push_back(static_cast<uint8_t>(length));
    } else {
        // Long form: first byte = 0x80 | num_octets, followed by length bytes
        std::vector<uint8_t> length_bytes;
        size_t temp = length;
        while (temp > 0) {
            length_bytes.insert(length_bytes.begin(), static_cast<uint8_t>(temp & 0xFF));
            temp >>= 8;
        }
        result.push_back(0x80 | static_cast<uint8_t>(length_bytes.size()));
        result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    }

    return result;
}

std::vector<uint8_t> encode_visible_string(const std::string& str) {
    std::vector<uint8_t> result;

    // Tag: 0x1a (VisibleString)
    result.push_back(0x1a);

    // Length
    std::vector<uint8_t> length_bytes = encode_length(str.length());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());

    // Content
    result.insert(result.end(), str.begin(), str.end());

    return result;
}

std::vector<uint8_t> encode_utf8_string(const std::string& str) {
    std::vector<uint8_t> result;

    // Tag: 0x0c (UTF8String)
    result.push_back(0x0c);

    // Length
    std::vector<uint8_t> length_bytes = encode_length(str.length());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());

    // Content
    result.insert(result.end(), str.begin(), str.end());

    return result;
}

std::vector<uint8_t> encode_sequence(const std::vector<std::vector<uint8_t>>& elements) {
    std::vector<uint8_t> result;

    // Calculate total length of all elements
    size_t total_length = 0;
    for (const auto& elem : elements) {
        total_length += elem.size();
    }

    // Tag: 0x30 (SEQUENCE)
    result.push_back(0x30);

    // Length
    std::vector<uint8_t> length_bytes = encode_length(total_length);
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());

    // Content (all elements)
    for (const auto& elem : elements) {
        result.insert(result.end(), elem.begin(), elem.end());
    }

    return result;
}

std::vector<uint8_t> encode_pkcs11_uri_der(const std::string& uri) {
    const std::string description = "PKCS#11 Provider URI v1.0";

    // Encode the two fields
    std::vector<uint8_t> desc_encoded = encode_visible_string(description);
    std::vector<uint8_t> uri_encoded = encode_utf8_string(uri);

    // Wrap in SEQUENCE
    std::vector<std::vector<uint8_t>> elements = {desc_encoded, uri_encoded};
    return encode_sequence(elements);
}

std::string der_to_pem(const std::vector<uint8_t>& der, const std::string& label) {
    // Base64 encode the DER data using OpenSSL
    // We need to do this manually since we're in the crypto layer

    // Use OpenSSL's base64 encoding
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // Write DER data
    BIO_write(bio, der.data(), static_cast<int>(der.size()));
    BIO_flush(bio);

    // Get the base64 string
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string base64_data(buffer_ptr->data, buffer_ptr->length);

    BIO_free_all(bio);

    // Build PEM format
    std::string pem;
    pem += "-----BEGIN " + label + "-----\n";
    pem += base64_data;
    // Note: OpenSSL's base64 encoder already adds newline at end
    if (!base64_data.empty() && base64_data.back() != '\n') {
        pem += "\n";
    }
    pem += "-----END " + label + "-----\n";

    return pem;
}

} // namespace asn1
} // namespace evse_security

#endif // USING_CUSTOM_PROVIDER

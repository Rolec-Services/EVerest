// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#pragma once

#include <evse_security/crypto/interface/crypto_types.hpp>
#include <evse_security/utils/evse_filesystem_types.hpp>

#include <optional>
#include <string>

namespace evse_security {

/// @brief Configuration for PKCS#11 HSM access
struct PKCS11Config {
    std::string module_path;
    int slot = 0;
    std::string token;
    std::string pin;
};

/// @brief Helper class for PKCS#11 HSM operations
class PKCS11Helper {
public:
    /// @brief Set the global PKCS#11 configuration (called once during module init)
    /// @param config The PKCS#11 configuration to use for all HSM operations
    static void set_config(const PKCS11Config& config);

    /// @brief Get the current global PKCS#11 configuration
    /// @return The active PKCS#11 configuration
    static const PKCS11Config& get_config();

    /// @brief Generate a key pair in the HSM and return its PKCS#11 URI
    /// @param key_type The type of key to generate (EC, RSA, etc.)
    /// @param key_label The label to assign to the key in the HSM
    /// @return PKCS#11 URI string if successful, std::nullopt on failure
    static std::optional<std::string> generate_key_in_hsm(CryptoKeyType key_type, const std::string& key_label);

    /// @brief Write a PKCS#11 URI to a PEM file in the special format
    /// @param pkcs11_uri The PKCS#11 URI to encode
    /// @param output_file Path to the output PEM file
    /// @return true if successful, false on failure
    static bool write_pkcs11_uri_pem_file(const std::string& pkcs11_uri, const fs::path& output_file);

private:
    static PKCS11Config s_config;

    /// @brief Map CryptoKeyType to pkcs11-tool key-type parameter string
    /// @param type The key type to map
    /// @return pkcs11-tool key-type parameter (e.g., "EC:prime256v1")
    static std::string get_pkcs11_key_type_param(CryptoKeyType type);

    /// @brief Generate a unique key ID for the HSM
    /// @param key_label The key label to base the ID on
    /// @return Hex-encoded key ID (2 bytes)
    static std::string generate_key_id(const std::string& key_label);
};

} // namespace evse_security

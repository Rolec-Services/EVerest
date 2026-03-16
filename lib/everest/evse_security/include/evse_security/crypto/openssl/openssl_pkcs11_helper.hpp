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
///
/// Uses the OpenSSL 3 EVP API with the pkcs11 provider to generate keys
/// directly in the HSM, rather than shelling out to pkcs11-tool. The pkcs11
/// provider configuration (module path, PIN, login behavior, etc.) is read
/// from the system openssl.cnf via the default OpenSSL library context.
class PKCS11Helper {
public:
    /// @brief Set the global PKCS#11 configuration (called once during module init)
    /// @param config The PKCS#11 configuration to use for all HSM operations
    static void set_config(const PKCS11Config& config);

    /// @brief Get the current global PKCS#11 configuration
    /// @return The active PKCS#11 configuration
    static const PKCS11Config& get_config();

    /// @brief Generate a key pair in the HSM and return its PKCS#11 URI
    ///
    /// Uses EVP_PKEY_generate() with the OpenSSL pkcs11 provider to create
    /// the key pair directly in the HSM. The provider handles PKCS#11 login,
    /// C_GenerateKeyPair, and key storage internally. The token and object
    /// label are specified via a pkcs11_uri parameter.
    ///
    /// @param key_type The type of key to generate (EC, RSA, etc.)
    /// @param key_label The label to assign to the key in the HSM
    /// @param libctx Optional OpenSSL library context to use. If provided, the pkcs11 provider
    ///               from this context is used for key generation. If nullptr, an internal
    ///               isolated context is created and destroyed within this call.
    /// @return PKCS#11 URI string if successful, std::nullopt on failure
    static std::optional<std::string> generate_key_in_hsm(CryptoKeyType key_type, const std::string& key_label,
                                                          void* libctx = nullptr);

    /// @brief Write a PKCS#11 URI to a PEM file in the special format
    /// @param pkcs11_uri The PKCS#11 URI to encode
    /// @param output_file Path to the output PEM file
    /// @return true if successful, false on failure
    static bool write_pkcs11_uri_pem_file(const std::string& pkcs11_uri, const fs::path& output_file);

    /// @brief Delete a key pair from the HSM by label
    ///
    /// Uses the PKCS#11 C API (via dlopen of the configured module) to find
    /// and destroy both the private and public key objects with the given label.
    ///
    /// @param key_label The label of the key to delete (the 'object=' value from the PKCS#11 URI)
    /// @return true if the key was found and deleted (or didn't exist), false on error
    static bool delete_key_from_hsm(const std::string& key_label);

    /// @brief Extract the key label from a .tkey PEM file
    ///
    /// Reads the PKCS#11 URI PEM file, decodes the ASN.1 structure, and extracts
    /// the 'object=' parameter (key label) from the embedded PKCS#11 URI.
    ///
    /// @param tkey_path Path to the .tkey PEM file
    /// @return The key label if successfully extracted, std::nullopt on failure
    static std::optional<std::string> extract_label_from_tkey_file(const fs::path& tkey_path);

    /// @brief Delete an HSM key associated with a .tkey file
    ///
    /// Convenience method that extracts the label from a .tkey file and deletes
    /// the corresponding key from the HSM. Safe to call on non-.tkey files (returns true).
    ///
    /// @param key_path Path to the key file (only acts on .tkey files)
    /// @return true if successful or not a .tkey file, false on HSM deletion error
    static bool delete_hsm_key_if_tkey(const fs::path& key_path);

private:
    static PKCS11Config s_config;
};

} // namespace evse_security

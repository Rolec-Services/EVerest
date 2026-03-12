// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include <evse_security/crypto/openssl/openssl_pkcs11_helper.hpp>

namespace evse_security {

// Static member definition
PKCS11Config PKCS11Helper::s_config;

void PKCS11Helper::set_config(const PKCS11Config& config) {
    s_config = config;
}

const PKCS11Config& PKCS11Helper::get_config() {
    return s_config;
}

} // namespace evse_security

#ifdef USING_CUSTOM_PROVIDER

#include <evse_security/crypto/openssl/openssl_asn1_der.hpp>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <everest/logging.hpp>

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace evse_security {

std::string PKCS11Helper::get_pkcs11_key_type_param(CryptoKeyType type) {
    switch (type) {
    case CryptoKeyType::EC_prime256v1:
        return "EC:prime256v1";
    case CryptoKeyType::EC_secp384r1:
        return "EC:secp384r1";
    case CryptoKeyType::RSA_2048: // Also handles RSA_TPM20 (alias)
        return "RSA:2048";
    case CryptoKeyType::RSA_3072:
        return "RSA:3072";
    case CryptoKeyType::RSA_7680:
        return "RSA:7680";
    default:
        EVLOG_error << "Unsupported key type for PKCS#11";
        return "";
    }
}

std::string PKCS11Helper::generate_key_id(const std::string& key_label) {
    // Generate a 2-byte key ID based on SHA256 hash of label
    // This ensures uniqueness while being deterministic
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(key_label.c_str()), key_label.length(), hash);

    // Use first 2 bytes as hex string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[0]) << std::setw(2)
        << static_cast<int>(hash[1]);

    return oss.str();
}

std::optional<std::string> PKCS11Helper::generate_key_in_hsm(CryptoKeyType key_type, const std::string& key_label) {
    const auto& config = s_config;
    EVLOG_info << "Generating PKCS#11 key in HSM: " << key_label;

    // Map key type to pkcs11-tool parameters
    std::string key_type_param = get_pkcs11_key_type_param(key_type);
    if (key_type_param.empty()) {
        EVLOG_error << "Invalid key type for PKCS#11";
        return std::nullopt;
    }

    // Generate unique key ID
    std::string key_id = generate_key_id(key_label);

    // Build pkcs11-tool command
    std::ostringstream cmd;
    cmd << "pkcs11-tool" << " --module " << config.module_path << " --login" << " --slot " << config.slot
        << " --keypairgen" << " --key-type " << key_type_param << " --label " << key_label << " --id " << key_id
        << " --usage-sign" << " --pin " << config.pin << " 2>&1"; // Capture stderr too

    EVLOG_info << "Executing: pkcs11-tool --module " << config.module_path << " --login --slot " << config.slot
               << " --keypairgen --key-type " << key_type_param << " --label " << key_label << " --id " << key_id
               << " --usage-sign --pin [REDACTED]";

    // Execute command
    FILE* pipe = popen(cmd.str().c_str(), "r");
    if (!pipe) {
        EVLOG_error << "Failed to execute pkcs11-tool command";
        return std::nullopt;
    }

    // Read output
    char buffer[256];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

    int exit_code = pclose(pipe);
    if (exit_code != 0) {
        EVLOG_error << "pkcs11-tool failed with exit code " << exit_code;
        EVLOG_error << "Output: " << output;
        return std::nullopt;
    }

    EVLOG_info << "Key pair generated successfully in HSM";
    EVLOG_debug << "pkcs11-tool output: " << output;

    // Build PKCS#11 URI
    std::ostringstream uri;
    uri << "pkcs11:" << "token=" << config.token << ";object=" << key_label << ";type=private";

    std::string uri_str = uri.str();
    EVLOG_info << "Generated PKCS#11 URI: " << uri_str;

    return uri_str;
}

bool PKCS11Helper::write_pkcs11_uri_pem_file(const std::string& pkcs11_uri, const fs::path& output_file) {
    EVLOG_info << "Writing PKCS#11 URI PEM file: " << output_file;

    try {
        // Encode URI as DER
        std::vector<uint8_t> der = asn1::encode_pkcs11_uri_der(pkcs11_uri);

        // Convert to PEM
        std::string pem = asn1::der_to_pem(der, "PKCS#11 PROVIDER URI");

        // Write to file
        std::ofstream file(output_file, std::ios::binary);
        if (!file) {
            EVLOG_error << "Failed to open file for writing: " << output_file;
            return false;
        }

        file << pem;
        file.close();

        if (!file.good()) {
            EVLOG_error << "Error writing PKCS#11 URI PEM file: " << output_file;
            return false;
        }

        EVLOG_info << "Successfully wrote PKCS#11 URI PEM file";
        return true;

    } catch (const std::exception& e) {
        EVLOG_error << "Exception while writing PKCS#11 URI PEM file: " << e.what();
        return false;
    }
}

} // namespace evse_security

#endif // USING_CUSTOM_PROVIDER

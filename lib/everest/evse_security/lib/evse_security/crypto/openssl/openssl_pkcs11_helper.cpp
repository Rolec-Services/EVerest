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

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>

#include <everest/logging.hpp>

#include <fstream>
#include <sstream>

namespace evse_security {

std::optional<std::string> PKCS11Helper::generate_key_in_hsm(CryptoKeyType key_type, const std::string& key_label) {
    const auto& config = s_config;
    EVLOG_info << "Generating PKCS#11 key pair in HSM via OpenSSL provider: " << key_label;

    // Determine algorithm name and EC group or RSA bits
    bool is_ec = true;
    std::string algorithm;
    std::string group;
    unsigned int bits = 0;

    switch (key_type) {
    case CryptoKeyType::EC_prime256v1:
        algorithm = "EC";
        group = "P-256";
        break;
    case CryptoKeyType::EC_secp384r1:
        algorithm = "EC";
        group = "P-384";
        break;
    case CryptoKeyType::RSA_2048: // RSA_TPM20 is an alias for RSA_2048
        algorithm = "RSA";
        is_ec = false;
        bits = 2048;
        break;
    case CryptoKeyType::RSA_3072:
        algorithm = "RSA";
        is_ec = false;
        bits = 3072;
        break;
    case CryptoKeyType::RSA_7680:
        algorithm = "RSA";
        is_ec = false;
        bits = 7680;
        break;
    default:
        EVLOG_error << "Unsupported key type for PKCS#11 key generation";
        return std::nullopt;
    }

    // Build PKCS#11 URI that tells the provider where to store the key on the token
    std::string pkcs11_uri = "pkcs11:token=" + config.token + ";object=" + key_label + ";type=private";

    EVLOG_info << "Requesting " << algorithm << " key generation via pkcs11 provider"
               << (is_ec ? (", group=" + group) : (", bits=" + std::to_string(bits)))
               << ", pkcs11_uri=" << pkcs11_uri;

    // Create a keygen context using the pkcs11 provider.
    // We use the default (NULL) library context which reads the system openssl.cnf.
    // This is where the PKCS#11 module path, PIN, login behavior and other provider
    // settings are configured (see /etc/ssl/openssl.cnf [pkcs11_sect]).
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, algorithm.c_str(), "provider=pkcs11");
    if (ctx == nullptr) {
        EVLOG_error << "Failed to create EVP_PKEY_CTX for " << algorithm << " with pkcs11 provider";
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    // Ensure cleanup on all exit paths
    auto ctx_cleanup = [](EVP_PKEY_CTX* p) { EVP_PKEY_CTX_free(p); };
    std::unique_ptr<EVP_PKEY_CTX, decltype(ctx_cleanup)> ctx_guard(ctx, ctx_cleanup);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVLOG_error << "EVP_PKEY_keygen_init failed for pkcs11 " << algorithm << " key generation";
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    // Set key generation parameters:
    //   - "group" (EC) or "bits" (RSA): defines the key size/curve
    //   - "pkcs11_uri": tells the pkcs11 provider which token and object label to use
    std::array<OSSL_PARAM, 3> params;
    if (is_ec) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                      const_cast<char*>(group.c_str()), 0);
    } else {
        params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_BITS, &bits);
    }
    params[1] = OSSL_PARAM_construct_utf8_string("pkcs11_uri",
                                                  const_cast<char*>(pkcs11_uri.c_str()), 0);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params.data()) <= 0) {
        EVLOG_error << "Failed to set keygen parameters for pkcs11 " << algorithm << " key generation";
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }

    // Generate the key pair in the HSM
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVLOG_error << "EVP_PKEY_generate failed for pkcs11 " << algorithm << " key generation";
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }
    EVP_PKEY_free(pkey);

    EVLOG_info << "Key pair generated successfully in HSM via OpenSSL pkcs11 provider";
    EVLOG_info << "PKCS#11 URI: " << pkcs11_uri;

    return pkcs11_uri;
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

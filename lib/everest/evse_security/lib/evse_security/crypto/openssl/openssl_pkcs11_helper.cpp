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
#include <evse_security/crypto/openssl/pkcs11_types.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>

#include <everest/logging.hpp>

#include <dlfcn.h>
#include <fstream>
#include <sstream>

namespace evse_security {

std::optional<std::string> PKCS11Helper::generate_key_in_hsm(CryptoKeyType key_type, const std::string& key_label,
                                                              void* caller_libctx) {
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

    // Use the caller-provided OSSL_LIB_CTX if available, otherwise create an isolated one.
    // When a caller provides a context, both key generation and subsequent key loading use
    // the same context — ensuring the pkcs11 provider's session can see the newly created key.
    OSSL_LIB_CTX* libctx = static_cast<OSSL_LIB_CTX*>(caller_libctx);
    std::unique_ptr<OSSL_LIB_CTX, void (*)(OSSL_LIB_CTX*)> libctx_guard(nullptr, OSSL_LIB_CTX_free);

    if (libctx == nullptr) {
        // No caller context — create an isolated one for this call only
        libctx = OSSL_LIB_CTX_new();
        if (libctx == nullptr) {
            EVLOG_error << "Failed to create isolated OSSL_LIB_CTX for key generation";
            return std::nullopt;
        }
        libctx_guard.reset(libctx); // Take ownership — will be freed when this function returns

        if (!OSSL_LIB_CTX_load_config(libctx, "/etc/ssl/openssl.cnf")) {
            EVLOG_error << "Failed to load OpenSSL config into isolated context";
            ERR_print_errors_fp(stderr);
            return std::nullopt;
        }
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(libctx, algorithm.c_str(), "provider=pkcs11");
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

bool PKCS11Helper::delete_key_from_hsm(const std::string& key_label) {
    const auto& config = s_config;
    EVLOG_info << "Deleting PKCS#11 key from HSM: " << key_label;

    if (config.module_path.empty()) {
        EVLOG_error << "PKCS#11 module path not configured, cannot delete key";
        return false;
    }

    // Load the PKCS#11 module via dlopen
    void* module = dlopen(config.module_path.c_str(), RTLD_NOW);
    if (module == nullptr) {
        EVLOG_error << "Failed to load PKCS#11 module " << config.module_path << ": " << dlerror();
        return false;
    }

    // RAII cleanup for the dlopen handle
    auto module_cleanup = [](void* m) {
        if (m != nullptr) {
            dlclose(m);
        }
    };
    std::unique_ptr<void, decltype(module_cleanup)> module_guard(module, module_cleanup);

    // Resolve the PKCS#11 functions we need via dlsym
    auto fn_Initialize = reinterpret_cast<PFN_C_Initialize>(dlsym(module, "C_Initialize"));
    auto fn_Finalize = reinterpret_cast<PFN_C_Finalize>(dlsym(module, "C_Finalize"));
    auto fn_OpenSession = reinterpret_cast<PFN_C_OpenSession>(dlsym(module, "C_OpenSession"));
    auto fn_CloseSession = reinterpret_cast<PFN_C_CloseSession>(dlsym(module, "C_CloseSession"));
    auto fn_Login = reinterpret_cast<PFN_C_Login>(dlsym(module, "C_Login"));
    auto fn_Logout = reinterpret_cast<PFN_C_Logout>(dlsym(module, "C_Logout"));
    auto fn_FindObjectsInit = reinterpret_cast<PFN_C_FindObjectsInit>(dlsym(module, "C_FindObjectsInit"));
    auto fn_FindObjects = reinterpret_cast<PFN_C_FindObjects>(dlsym(module, "C_FindObjects"));
    auto fn_FindObjectsFinal = reinterpret_cast<PFN_C_FindObjectsFinal>(dlsym(module, "C_FindObjectsFinal"));
    auto fn_DestroyObject = reinterpret_cast<PFN_C_DestroyObject>(dlsym(module, "C_DestroyObject"));

    if (!fn_Initialize || !fn_Finalize || !fn_OpenSession || !fn_CloseSession || !fn_Login || !fn_Logout ||
        !fn_FindObjectsInit || !fn_FindObjects || !fn_FindObjectsFinal || !fn_DestroyObject) {
        EVLOG_error << "Failed to resolve required PKCS#11 functions from " << config.module_path;
        return false;
    }

    // Initialize the PKCS#11 library.
    // If the library is already initialized (e.g., by the OpenSSL pkcs11 provider running
    // in the same process), CKR_CRYPTOKI_ALREADY_INITIALIZED is returned — this is fine,
    // we can still open sessions. We just must not call C_Finalize in that case, as it
    // would tear down sessions owned by the provider.
    CK_RV rv = fn_Initialize(nullptr);
    bool we_initialized = (rv == CKR_OK);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        EVLOG_error << "C_Initialize failed: 0x" << std::hex << rv;
        return false;
    }

    bool success = true;
    CK_SESSION_HANDLE session = 0;

    // Open a read-write session
    rv = fn_OpenSession(static_cast<CK_SLOT_ID>(config.slot), CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                        &session);
    if (rv != CKR_OK) {
        EVLOG_error << "C_OpenSession failed: 0x" << std::hex << rv;
        if (we_initialized) fn_Finalize(nullptr);
        return false;
    }

    // Login. If the user is already logged in (e.g., by the OpenSSL pkcs11 provider's
    // login-behavior=always setting), CKR_USER_ALREADY_LOGGED_IN is returned — this is
    // fine. We track whether we logged in so we don't logout on someone else's session.
    std::string pin_copy = config.pin;
    rv = fn_Login(session, CKU_USER, reinterpret_cast<CK_UTF8CHAR*>(pin_copy.data()),
                  static_cast<CK_ULONG>(pin_copy.size()));
    bool we_logged_in = (rv == CKR_OK);
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        EVLOG_error << "C_Login failed: 0x" << std::hex << rv;
        fn_CloseSession(session);
        if (we_initialized) fn_Finalize(nullptr);
        return false;
    }

    // Find and destroy both private and public key objects with the given label
    const CK_OBJECT_CLASS object_classes[] = {CKO_PRIVATE_KEY, CKO_PUBLIC_KEY};
    const char* class_names[] = {"private key", "public key"};

    for (int i = 0; i < 2; i++) {
        CK_OBJECT_CLASS obj_class = object_classes[i];
        std::string label_copy = key_label;

        CK_ATTRIBUTE search_template[2];
        search_template[0].type = CKA_CLASS;
        search_template[0].pValue = &obj_class;
        search_template[0].ulValueLen = sizeof(obj_class);
        search_template[1].type = CKA_LABEL;
        search_template[1].pValue = label_copy.data();
        search_template[1].ulValueLen = static_cast<CK_ULONG>(label_copy.size());

        rv = fn_FindObjectsInit(session, search_template, 2);
        if (rv != CKR_OK) {
            EVLOG_error << "C_FindObjectsInit failed for " << class_names[i] << ": 0x" << std::hex << rv;
            success = false;
            continue;
        }

        CK_OBJECT_HANDLE handle = 0;
        CK_ULONG found_count = 0;
        rv = fn_FindObjects(session, &handle, 1, &found_count);
        fn_FindObjectsFinal(session);

        if (rv != CKR_OK) {
            EVLOG_error << "C_FindObjects failed for " << class_names[i] << ": 0x" << std::hex << rv;
            success = false;
            continue;
        }

        if (found_count > 0) {
            rv = fn_DestroyObject(session, handle);
            if (rv != CKR_OK) {
                EVLOG_error << "C_DestroyObject failed for " << class_names[i] << " '" << key_label
                            << "': 0x" << std::hex << rv;
                success = false;
            } else {
                EVLOG_info << "Destroyed " << class_names[i] << " '" << key_label << "' from HSM";
            }
        } else {
            EVLOG_debug << "No " << class_names[i] << " found with label '" << key_label << "' (already deleted?)";
        }
    }

    if (we_logged_in) {
        fn_Logout(session);
    }
    fn_CloseSession(session);
    if (we_initialized) {
        fn_Finalize(nullptr);
    }

    return success;
}

std::optional<std::string> PKCS11Helper::extract_label_from_tkey_file(const fs::path& tkey_path) {
    try {
        // Read the .tkey PEM file
        std::ifstream file(tkey_path);
        if (!file) {
            EVLOG_error << "Failed to open .tkey file: " << tkey_path;
            return std::nullopt;
        }

        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Extract base64 content between PEM armor lines
        const std::string begin_marker = "-----BEGIN PKCS#11 PROVIDER URI-----";
        const std::string end_marker = "-----END PKCS#11 PROVIDER URI-----";

        auto begin_pos = content.find(begin_marker);
        auto end_pos = content.find(end_marker);
        if (begin_pos == std::string::npos || end_pos == std::string::npos) {
            EVLOG_error << "Invalid .tkey PEM format: " << tkey_path;
            return std::nullopt;
        }

        std::string base64_data = content.substr(begin_pos + begin_marker.size(), end_pos - begin_pos - begin_marker.size());

        // Base64 decode using OpenSSL
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new_mem_buf(base64_data.data(), static_cast<int>(base64_data.size()));
        bio = BIO_push(b64, bio);

        // DER output buffer (the encoded URI is typically < 200 bytes)
        std::vector<uint8_t> der(base64_data.size());
        int der_len = BIO_read(bio, der.data(), static_cast<int>(der.size()));
        BIO_free_all(bio);

        if (der_len <= 0) {
            EVLOG_error << "Failed to base64-decode .tkey content: " << tkey_path;
            return std::nullopt;
        }
        der.resize(static_cast<size_t>(der_len));

        // The DER structure is:
        //   SEQUENCE {
        //     VisibleString("PKCS#11 Provider URI v1.0")
        //     UTF8String("pkcs11:token=...;object=LABEL;type=private")
        //   }
        // The URI is ASCII text, so we can search for "object=" in the raw DER bytes.
        std::string der_str(der.begin(), der.end());
        const std::string object_prefix = "object=";
        auto obj_pos = der_str.find(object_prefix);
        if (obj_pos == std::string::npos) {
            EVLOG_error << "No 'object=' field found in PKCS#11 URI from: " << tkey_path;
            return std::nullopt;
        }

        // Extract the label: from after "object=" to the next ';' or end of URI
        auto label_start = obj_pos + object_prefix.size();
        auto label_end = der_str.find(';', label_start);
        if (label_end == std::string::npos) {
            // The object= might be the last field — find the end of the UTF8String
            // The URI ends at the last printable character before the DER structure ends
            label_end = der_str.size();
        }

        std::string label = der_str.substr(label_start, label_end - label_start);
        if (label.empty()) {
            EVLOG_error << "Empty key label extracted from: " << tkey_path;
            return std::nullopt;
        }

        EVLOG_debug << "Extracted key label '" << label << "' from: " << tkey_path;
        return label;

    } catch (const std::exception& e) {
        EVLOG_error << "Exception while extracting label from .tkey file: " << e.what();
        return std::nullopt;
    }
}

bool PKCS11Helper::delete_hsm_key_if_tkey(const fs::path& key_path) {
    // Only act on .tkey files (PKCS#11 URI PEM files pointing to HSM keys)
    if (key_path.extension() != ".tkey") {
        return true;
    }

    auto label_opt = extract_label_from_tkey_file(key_path);
    if (!label_opt.has_value()) {
        EVLOG_error << "Failed to extract key label from .tkey file for HSM deletion: " << key_path;
        return false;
    }

    return delete_key_from_hsm(label_opt.value());
}

} // namespace evse_security

#endif // USING_CUSTOM_PROVIDER

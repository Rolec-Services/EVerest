// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#include <evse_security/crypto/openssl/openssl_crypto_supplier.hpp>

#include <everest/logging.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iterator>
#include <numeric>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/x509v3.h>

#include <evse_security/crypto/openssl/openssl_provider.hpp>
#include <evse_security/crypto/openssl/openssl_types.hpp>
#include <evse_security/utils/evse_filesystem.hpp>

#ifdef USING_CUSTOM_PROVIDER
#include <evse_security/crypto/openssl/openssl_pkcs11_helper.hpp>
#endif

namespace evse_security {

namespace {
X509* get(X509Handle* handle) {
    if (auto* ssl_handle = dynamic_cast<X509HandleOpenSSL*>(handle)) {
        return ssl_handle->get();
    }

    return nullptr;
}

EVP_PKEY* get(KeyHandle* handle) {
    if (auto* ssl_handle = dynamic_cast<KeyHandleOpenSSL*>(handle)) {
        return ssl_handle->get();
    }

    return nullptr;
}

CertificateValidationResult to_certificate_error(const int ec) {
    EVLOG_warning << "Certificate verification failed with OpenSSL error code " << ec
                  << " (" << X509_verify_cert_error_string(ec) << ")";

    switch (ec) {
    case X509_V_ERR_CERT_HAS_EXPIRED:
        EVLOG_warning << "  -> Mapped to: Expired";
        return CertificateValidationResult::Expired;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        EVLOG_warning << "  -> Mapped to: InvalidSignature";
        return CertificateValidationResult::InvalidSignature;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        EVLOG_warning << "  -> Mapped to: IssuerNotFound";
        return CertificateValidationResult::IssuerNotFound;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        EVLOG_warning << "  -> Mapped to: InvalidLeafSignature";
        return CertificateValidationResult::InvalidLeafSignature;
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    case X509_V_ERR_CERT_UNTRUSTED:
        EVLOG_warning << "  -> Mapped to: InvalidChain";
        return CertificateValidationResult::InvalidChain;
    default:
        EVLOG_warning << "  -> Unmapped error code " << ec << ", returning Unknown";
        return CertificateValidationResult::Unknown;
    }
}
} // namespace

const char* OpenSSLSupplier::get_supplier_name() {
    return OPENSSL_VERSION_TEXT;
}

bool OpenSSLSupplier::supports_tpm_key_creation() {
    const OpenSSLProvider provider;
    return provider.supports_provider_tpm();
}

namespace {
bool export_key_internal(const KeyGenerationInfo& key_info, const EVP_PKEY_ptr& evp_key) {
    // write private key to file
    if (key_info.private_key_file.has_value()) {
        const BIO_ptr key_bio(BIO_new_file(key_info.private_key_file.value().c_str(), "w"));

        if (!key_bio) {
            EVLOG_error << "Failed to create private key file!";
            return false;
        }

        int success = 0;
        if (key_info.private_key_pass.has_value()) {
            success = PEM_write_bio_PrivateKey(key_bio.get(), evp_key.get(), EVP_aes_128_cbc(), nullptr, 0, nullptr,
                                               (void*)key_info.private_key_pass.value().c_str());
        } else {
            success = PEM_write_bio_PrivateKey(key_bio.get(), evp_key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        }

        if (0 == success) {
            EVLOG_error << "Failed to write private key!";
            return false;
        }
    }

    if (key_info.public_key_file.has_value()) {
        const BIO_ptr key_bio(BIO_new_file(key_info.public_key_file.value().c_str(), "w"));

        if (!key_bio) {
            EVLOG_error << "Failed to create private key file!";
            return false;
        }

        if (0 == PEM_write_bio_PUBKEY(key_bio.get(), evp_key.get())) {
            EVLOG_error << "Failed to write pubkey!";
            return false;
        }
    }

    return true;
}
} // namespace

constexpr const char* kt_rsa = "RSA";
constexpr const char* kt_ec = "EC";

namespace {
bool s_generate_key(const KeyGenerationInfo& key_info, KeyHandle_ptr& out_key, EVP_PKEY_CTX_ptr& ctx) {
    unsigned int bits = 0;
    std::string group_256 = "P-256";
    std::string group_384 = "P-384";
    char* group = nullptr;
    std::size_t group_sz = 0;
    int nid = NID_undef;

    bool bResult = true;
    bool bEC = true;

    OpenSSLProvider provider;

#ifdef USING_CUSTOM_PROVIDER
    if (key_info.generate_on_custom) {
        // We use a single dedicated OSSL_LIB_CTX for all PKCS#11 operations (key generation
        // and key loading). This is necessary because:
        //
        //   1. The default context's pkcs11 provider has cached read-only TLS sessions, causing
        //      session conflicts for both key generation and key loading.
        //   2. Key generation and key loading must use the SAME context so the provider's
        //      session can see newly created keys immediately.
        //   3. The context must persist after this function returns, because the loaded EVP_PKEY
        //      is bound to the provider instance within this context. If the context is destroyed,
        //      the provider's encoders become unavailable and CSR generation fails with
        //      "No encoders were found" at X509_PUBKEY_set.
        //
        // We recreate the context on each call to ensure a fresh PKCS#11 session — this avoids
        // stale session caches that can't see keys created in previous invocations.
        static OSSL_LIB_CTX* s_pkcs11_libctx = nullptr;

        // Free the previous context (and its provider instances / sessions)
        if (s_pkcs11_libctx != nullptr) {
            OSSL_LIB_CTX_free(s_pkcs11_libctx);
            s_pkcs11_libctx = nullptr;
        }

        s_pkcs11_libctx = OSSL_LIB_CTX_new();
        if (s_pkcs11_libctx == nullptr) {
            EVLOG_error << "Failed to create OSSL_LIB_CTX for PKCS#11 operations";
            return false;
        }
        if (!OSSL_LIB_CTX_load_config(s_pkcs11_libctx, "/etc/ssl/openssl.cnf")) {
            EVLOG_error << "Failed to load OpenSSL config into PKCS#11 context";
            ERR_print_errors_fp(stderr);
            OSSL_LIB_CTX_free(s_pkcs11_libctx);
            s_pkcs11_libctx = nullptr;
            return false;
        }

        // Derive key label from filename
        std::string key_label =
            key_info.private_key_file.has_value() ? key_info.private_key_file.value().stem().string() : "generated_key";

        // Generate key in HSM using our dedicated context
        auto uri_opt = PKCS11Helper::generate_key_in_hsm(key_info.key_type, key_label, s_pkcs11_libctx);
        if (!uri_opt.has_value()) {
            EVLOG_error << "Failed to generate key in PKCS#11 HSM";
            return false;
        }

        // From this point on, a key exists on the HSM token. If any subsequent step fails,
        // we must delete it to prevent orphan keys from accumulating and filling the token.
        // This lambda captures key_label and is called on every failure path below.
        auto rollback_hsm_key = [&key_label]() {
            EVLOG_warning << "Rolling back HSM key after failure: " << key_label;
            PKCS11Helper::delete_key_from_hsm(key_label);
        };

        // Write PKCS#11 URI to PEM file
        if (key_info.private_key_file.has_value()) {
            if (!PKCS11Helper::write_pkcs11_uri_pem_file(uri_opt.value(), key_info.private_key_file.value())) {
                EVLOG_error << "Failed to write PKCS#11 URI PEM file";
                rollback_hsm_key();
                return false;
            }
        }

        // Load the private key from the HSM via the PKCS#11 URI using OpenSSL's OSSL_STORE API.
        // We use the SAME context that generated the key, so the provider's session sees it.
        const std::string& pkcs11_uri = uri_opt.value();

        OSSL_STORE_CTX* store_ctx =
            OSSL_STORE_open_ex(pkcs11_uri.c_str(), s_pkcs11_libctx, nullptr, nullptr, nullptr, nullptr,
                               nullptr, nullptr);
        if (store_ctx == nullptr) {
            EVLOG_error << "Failed to open OSSL_STORE for PKCS#11 URI: " << pkcs11_uri;
            ERR_print_errors_fp(stderr);
            rollback_hsm_key();
            return false;
        }

        EVP_PKEY* pkey = nullptr;
        while (!OSSL_STORE_eof(store_ctx)) {
            OSSL_STORE_INFO* info = OSSL_STORE_load(store_ctx);
            if (info == nullptr) {
                continue;
            }

            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
                OSSL_STORE_INFO_free(info);
                break;
            }
            OSSL_STORE_INFO_free(info);
        }
        OSSL_STORE_close(store_ctx);

        if (pkey == nullptr) {
            EVLOG_error << "Failed to load private key from PKCS#11 URI: " << pkcs11_uri;
            ERR_print_errors_fp(stderr);
            rollback_hsm_key();
            return false;
        }

        auto evp_key = EVP_PKEY_ptr(pkey);

        // Export public key if requested
        if (key_info.public_key_file.has_value()) {
            const BIO_ptr pub_bio(BIO_new_file(key_info.public_key_file.value().c_str(), "w"));
            if (!pub_bio || 0 == PEM_write_bio_PUBKEY(pub_bio.get(), evp_key.get())) {
                EVLOG_error << "Failed to write public key!";
                rollback_hsm_key();
                return false;
            }
        }

        // Return the key handle. The static s_pkcs11_libctx persists, keeping the provider's
        // encoders alive so the EVP_PKEY can be used for CSR generation (X509_PUBKEY_set, etc.)
        EVP_PKEY* raw_key_handle = evp_key.release();
        out_key = std::make_unique<KeyHandleOpenSSL>(raw_key_handle);

        return true;
    }
    // generate_on_custom is false: fall through to standard OpenSSL key generation below
#endif

    // Standard OpenSSL key generation (software)
    if (key_info.generate_on_custom) {
        provider.set_global_mode(OpenSSLProvider::mode_t::custom_provider);
    } else {
        provider.set_global_mode(OpenSSLProvider::mode_t::default_provider);
    }

    // note when using tpm2 some key_types may not be supported.

    EVLOG_info << "Key parameters";
    switch (key_info.key_type) {
    case CryptoKeyType::RSA_TPM20:
        bits = 2048;
        bEC = false;
        break;
    case CryptoKeyType::RSA_3072:
        bits = 3072;
        bEC = false;
        break;
    case CryptoKeyType::RSA_7680:
        bits = 7680;
        bEC = false;
        break;
    case CryptoKeyType::EC_prime256v1:
        group = group_256.data();
        group_sz = group_256.length();
        nid = NID_X9_62_prime256v1;
        break;
    case CryptoKeyType::EC_secp384r1:
    default:
        group = group_384.data();
        group_sz = group_384.length();
        nid = NID_secp384r1;
        break;
    }

    std::array<OSSL_PARAM, 2> params = {};

    if (bEC) {
        params[0] = OSSL_PARAM_construct_utf8_string("group", group, group_sz);
        EVLOG_info << "Key parameters: EC";
        ctx = EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_from_name(nullptr, kt_ec, nullptr));
    } else {
        params[0] = OSSL_PARAM_construct_uint("bits", &bits);
        EVLOG_info << "Key parameters: RSA";
        ctx = EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_from_name(nullptr, kt_rsa, nullptr));
    }

    params[1] = OSSL_PARAM_construct_end();

    if (bResult) {
        EVLOG_info << "Key parameters done";
        if (nullptr == ctx.get()) {
            EVLOG_error << "create key context failed!";
            ERR_print_errors_fp(stderr);
            bResult = false;
        }
    }

    if (bResult) {
        EVLOG_info << "Keygen init";
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_CTX_set_params(ctx.get(), params.data()) <= 0) {
            EVLOG_error << "Keygen init failed";
            ERR_print_errors_fp(stderr);
            bResult = false;
        }
    }

    EVP_PKEY* pkey = nullptr;

    if (bResult) {
        EVLOG_info << "Key generate";
        if (EVP_PKEY_generate(ctx.get(), &pkey) <= 0) {
            EVLOG_error << "Failed to generate tpm2 key!";
            ERR_print_errors_fp(stderr);
            bResult = false;
        }
    }

    auto evp_key = EVP_PKEY_ptr(pkey);

    if (bResult) {
        EVLOG_info << "Key export";
        // Export keys too
        bResult = export_key_internal(key_info, evp_key);
        // NOLINTNEXTLINE(misc-const-correctness): would be problematic in the following make_unique statement
        EVP_PKEY* raw_key_handle = evp_key.release();
        out_key = std::make_unique<KeyHandleOpenSSL>(raw_key_handle);
    }

    return bResult;
}
} // namespace

bool OpenSSLSupplier::generate_key(const KeyGenerationInfo& key_info, KeyHandle_ptr& /*out_key*/) {
    KeyHandle_ptr gen_key;
    EVP_PKEY_CTX_ptr ctx;
    bool bResult = true;

    bResult = s_generate_key(key_info, gen_key, ctx);
    if (!bResult) {
        EVLOG_error << "Failed to generate csr pub/priv key!";
    }

    return bResult;
}

std::vector<X509Handle_ptr> OpenSSLSupplier::load_certificates(const std::string& data, const EncodingFormat encoding) {
    std::vector<X509Handle_ptr> certificates;

    const BIO_ptr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));

    if (!bio) {
        throw CertificateLoadException("Failed to create BIO from data");
    }

    if (encoding == EncodingFormat::PEM) {
        STACK_OF(X509_INFO)* allcerts = PEM_X509_INFO_read_bio(bio.get(), nullptr, nullptr, nullptr);

        if (allcerts != nullptr) {
            for (int i = 0; i < sk_X509_INFO_num(allcerts); i++) {
                X509_INFO* xi = sk_X509_INFO_value(allcerts, i);

                if ((xi != nullptr) && (xi->x509 != nullptr)) {
                    // Transfer ownership, safely, push_back since emplace_back can cause a memory leak
                    certificates.push_back(std::make_unique<X509HandleOpenSSL>(xi->x509));
                    xi->x509 = nullptr;
                }
            }

            sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
        } else {
            throw CertificateLoadException("Certificate (PEM) parsing error");
        }
    } else if (encoding == EncodingFormat::DER) {
        // NOLINTNEXTLINE(misc-const-correctness): would be problematic in the following make_unique statement
        X509* x509 = d2i_X509_bio(bio.get(), nullptr);

        if (x509 != nullptr) {
            certificates.push_back(std::make_unique<X509HandleOpenSSL>(x509));
        } else {
            throw CertificateLoadException("Certificate (DER) parsing error");
        }
    } else {
        throw CertificateLoadException("Unsupported encoding format");
    }

    return certificates;
}

std::string OpenSSLSupplier::x509_to_string(X509Handle* handle) {
    // NOLINTNEXTLINE(misc-const-correctness): would be problematic in the following PEM_write_bio_X509 statement
    if (X509* x509 = get(handle)) {
        const BIO_ptr bio_write(BIO_new(BIO_s_mem()));

        const int rc = PEM_write_bio_X509(bio_write.get(), x509);

        if (rc == 1) {
            const BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio_write.get(), &mem);

            return std::string(mem->data, mem->length);
        }
    }

    return {};
}

std::string OpenSSLSupplier::x509_get_common_name(X509Handle* handle) {
    const X509* x509 = get(handle);

    if (x509 == nullptr) {
        return {};
    }

    const X509_NAME* subject = X509_get_subject_name(x509);
    const int nid = OBJ_txt2nid("CN");
    const int index = X509_NAME_get_index_by_NID(subject, nid, -1);

    if (index == -1) {
        return {};
    }

    const X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, index);
    const ASN1_STRING* ca_asn1 = X509_NAME_ENTRY_get_data(entry);

    if (ca_asn1 == nullptr) {
        return {};
    }

    const unsigned char* cn_str = ASN1_STRING_get0_data(ca_asn1);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
    std::string common_name(reinterpret_cast<const char*>(cn_str), ASN1_STRING_length(ca_asn1));
    return common_name;
}

std::string OpenSSLSupplier::x509_get_issuer_name_hash(X509Handle* handle) {
    const X509* x509 = get(handle);

    if (x509 == nullptr) {
        return {};
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> md;
    const X509_NAME* name = X509_get_issuer_name(x509);
    X509_NAME_digest(name, EVP_sha256(), md.data(), nullptr);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)md.at(i);
    }
    return ss.str();
}

std::string OpenSSLSupplier::x509_get_serial_number(X509Handle* handle) {
    X509* x509 = get(handle);

    if (x509 == nullptr) {
        return {};
    }

    const ASN1_INTEGER* serial_asn1 = X509_get_serialNumber(x509);
    if (serial_asn1 == nullptr) {
        ERR_print_errors_fp(stderr);
        return {};
    }

    BIGNUM* bn_serial = ASN1_INTEGER_to_BN(serial_asn1, nullptr);

    if (bn_serial == nullptr) {
        ERR_print_errors_fp(stderr);
        return {};
    }

    char* hex_serial = BN_bn2hex(bn_serial);

    if (hex_serial == nullptr) {
        ERR_print_errors_fp(stderr);
        return {};
    }

    std::string serial(hex_serial);
    for (char& i : serial) {
        i = static_cast<char>(std::tolower(static_cast<unsigned char>(i)));
    }

    BN_free(bn_serial);
    OPENSSL_free(hex_serial);

    serial.erase(0, std::min(serial.find_first_not_of('0'), serial.size() - 1));
    return serial;
}

std::string OpenSSLSupplier::x509_get_key_hash(X509Handle* handle) {
    const X509* x509 = get(handle);

    if (x509 == nullptr) {
        return {};
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> tmphash;
    X509_pubkey_digest(x509, EVP_sha256(), tmphash.data(), nullptr);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)tmphash.at(i);
    }

    return ss.str();
}

std::string OpenSSLSupplier::x509_get_responder_url(X509Handle* handle) {
    X509* x509 = get(handle);

    if (x509 == nullptr) {
        return {};
    }

    const auto ocsp = X509_get1_ocsp(x509);
    std::string responder_url;
    for (int i = 0; i < sk_OPENSSL_STRING_num(ocsp); i++) {
        responder_url.append(sk_OPENSSL_STRING_value(ocsp, i));
    }

    if (responder_url.empty()) {
        EVLOG_warning << "Could not retrieve OCSP Responder URL from certificate";
    }

    return responder_url;
}

bool OpenSSLSupplier::x509_get_validity(X509Handle* handle, std::int64_t& out_valid_in, std::int64_t& out_valid_to) {
    const X509* x509 = get(handle);

    if (x509 == nullptr) {
        return false;
    }

    // For valid_in and valid_to
    const ASN1_TIME* notBefore = X509_get_notBefore(x509);
    const ASN1_TIME* notAfter = X509_get_notAfter(x509);

    int day = 0;
    int sec = 0;
    ASN1_TIME_diff(&day, &sec, nullptr, notBefore);
    out_valid_in =
        std::chrono::duration_cast<std::chrono::seconds>(days_to_seconds(day)).count() + sec; // Convert days to seconds
    ASN1_TIME_diff(&day, &sec, nullptr, notAfter);
    out_valid_to =
        std::chrono::duration_cast<std::chrono::seconds>(days_to_seconds(day)).count() + sec; // Convert days to seconds

    return true;
}

bool OpenSSLSupplier::x509_is_child(X509Handle* child, X509Handle* parent) {
    // A certif can't be it's own parent, use is_selfsigned if that is intended
    if (child == parent) {
        return false;
    }

    X509* x509_parent = get(parent);
    X509* x509_child = get(child);

    if (x509_parent == nullptr || x509_child == nullptr) {
        return false;
    }

    const X509_STORE_ptr store(X509_STORE_new());
    X509_STORE_add_cert(store.get(), x509_parent);

    const X509_STORE_CTX_ptr ctx(X509_STORE_CTX_new());
    X509_STORE_CTX_init(ctx.get(), store.get(), x509_child, nullptr);

    // Do not enforce notBefore/notAfter when checking parentage. This function answers the
    // purely cryptographic question "was this cert issued by that cert?" — validity dates are
    // irrelevant here and would cause freshly-issued certs (whose notBefore may be a few
    // seconds in the future due to CA/charger clock skew) to be incorrectly orphaned in the
    // hierarchy, breaking find_certificate_root() and the TLS server reconfiguration.
    X509_STORE_CTX_set_flags(ctx.get(), X509_V_FLAG_NO_CHECK_TIME);

    // If the parent is not a self-signed certificate, assume we have a partial chain
    if (x509_is_selfsigned(parent) == false) {
        // TODO(ioan): see if this strict flag is required, caused many problems
        // X509_STORE_CTX_set_flags(ctx.get(), X509_V_FLAG_X509_STRICT);

        X509_STORE_CTX_set_flags(ctx.get(), X509_V_FLAG_PARTIAL_CHAIN);
    }

    if (X509_verify_cert(ctx.get()) != 1) {
        const int ec = X509_STORE_CTX_get_error(ctx.get());
        const char* error = X509_verify_cert_error_string(ec);

        EVLOG_debug << "Certificate issued by error: " << ((error != nullptr) ? error : "UNKNOWN");
        return false;
    }

    return true;
}

bool OpenSSLSupplier::x509_is_selfsigned(X509Handle* handle) {
    X509* x509 = get(handle);

    if (x509 == nullptr) {
        return false;
    }

    return (X509_self_signed(x509, 0) == 1);
}

bool OpenSSLSupplier::x509_is_equal(X509Handle* a, X509Handle* b) {
    return (X509_cmp(get(a), get(b)) == 0);
}

X509Handle_ptr OpenSSLSupplier::x509_duplicate_unique(X509Handle* handle) {
    return std::make_unique<X509HandleOpenSSL>(X509_dup(get(handle)));
}

CertificateValidationResult OpenSSLSupplier::x509_verify_certificate_chain(
    X509Handle* target, const std::vector<X509Handle*>& parents, const std::vector<X509Handle*>& untrusted_subcas,
    bool allow_future_certificates, const std::optional<fs::path> dir_path, const std::optional<fs::path> file_path) {

    const X509_STORE_ptr store_ptr(X509_STORE_new());
    const X509_STORE_CTX_ptr store_ctx_ptr(X509_STORE_CTX_new());

    for (auto parent : parents) {
        X509_STORE_add_cert(store_ptr.get(), get(parent));
    }

    if (dir_path.has_value() || file_path.has_value()) {
        const char* c_dir_path = dir_path.has_value() ? dir_path.value().c_str() : nullptr;
        const char* c_file_path = file_path.has_value() ? file_path.value().c_str() : nullptr;

        if (1 != X509_STORE_load_locations(store_ptr.get(), c_file_path, c_dir_path)) {
            EVLOG_warning << "X509 could not load store locations!";
            return CertificateValidationResult::Unknown;
        }

        if (dir_path.has_value()) {
            if (X509_STORE_add_lookup(store_ptr.get(), X509_LOOKUP_file()) == nullptr) {
                EVLOG_warning << "X509 could not add store lookup!";
                return CertificateValidationResult::Unknown;
            }
        }
    }

    X509_STACK_UNSAFE_ptr untrusted = nullptr;

    // Build potentially untrusted intermediary (subca) certificates
    if (false == untrusted_subcas.empty()) {
        untrusted = X509_STACK_UNSAFE_ptr(sk_X509_new_null());
        const int flags = X509_ADD_FLAG_NO_DUP | X509_ADD_FLAG_NO_SS;

        for (auto& untrusted_cert : untrusted_subcas) {
            if (1 != X509_add_cert(untrusted.get(), get(untrusted_cert), flags)) {
                EVLOG_error << "X509 could not create untrusted store stack!";
                return CertificateValidationResult::Unknown;
            }
        }
    }

    if (1 != X509_STORE_CTX_init(store_ctx_ptr.get(), store_ptr.get(), get(target), untrusted.get())) {
        EVLOG_error << "X509 could not init x509 store ctx!";
        return CertificateValidationResult::Unknown;
    }

    if (allow_future_certificates) {
        // Manually check if cert is expired
        int day = 0;
        int sec = 0;
        ASN1_TIME_diff(&day, &sec, nullptr, X509_get_notAfter(get(target)));
        if (day < 0 || sec < 0) {
            // certificate is expired
            return CertificateValidationResult::Expired;
        }
        // certificate is not expired, but may not be valid yet. Since we allow future certs, disable time checks.
        X509_STORE_CTX_set_flags(store_ctx_ptr.get(), X509_V_FLAG_NO_CHECK_TIME);
    }

    // Log details about the certificate being verified
    {
        X509* target_cert = get(target);
        if (target_cert != nullptr) {
            char subject_buf[256] = {};
            char issuer_buf[256] = {};
            X509_NAME_oneline(X509_get_subject_name(target_cert), subject_buf, sizeof(subject_buf));
            X509_NAME_oneline(X509_get_issuer_name(target_cert), issuer_buf, sizeof(issuer_buf));

            EVLOG_info << "Verifying certificate chain:";
            EVLOG_info << "  Subject: " << subject_buf;
            EVLOG_info << "  Issuer:  " << issuer_buf;
            EVLOG_info << "  Trusted parent certs: " << parents.size();
            EVLOG_info << "  Untrusted intermediates: " << untrusted_subcas.size();
            EVLOG_info << "  Allow future certs: " << (allow_future_certificates ? "yes" : "no");

            // Log the public key type and encoding details
            EVP_PKEY* pubkey = X509_get0_pubkey(target_cert);
            if (pubkey != nullptr) {
                int key_type = EVP_PKEY_id(pubkey);
                int key_bits = EVP_PKEY_bits(pubkey);
                EVLOG_info << "  Public key type: " << OBJ_nid2sn(key_type) << " (" << key_bits << " bits)";

                // Check if EC key uses explicit parameters (the issue we're investigating)
                if (key_type == EVP_PKEY_EC) {
                    char group_name[64] = {};
                    size_t group_name_len = 0;
                    if (EVP_PKEY_get_utf8_string_param(pubkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name,
                                                       sizeof(group_name), &group_name_len)) {
                        EVLOG_info << "  EC curve (named): " << group_name;
                    } else {
                        EVLOG_warning << "  EC curve: COULD NOT RETRIEVE NAMED CURVE (likely explicit parameters)";
                        ERR_clear_error(); // Clear the error from the failed param retrieval
                    }

                    // Check the encoding size — explicit params produce much larger encodings
                    int der_len = i2d_PUBKEY(pubkey, nullptr);
                    EVLOG_info << "  Public key DER encoding size: " << der_len << " bytes"
                               << (der_len > 100 ? " (LARGE - likely explicit EC parameters)" : " (normal - named curve)");
                }
            }
        }
    }

    // verifies the certificate chain based on ctx
    // verifies the certificate has not expired and is already valid
    if (X509_verify_cert(store_ctx_ptr.get()) != 1) {
        const int ec = X509_STORE_CTX_get_error(store_ctx_ptr.get());
        const int depth = X509_STORE_CTX_get_error_depth(store_ctx_ptr.get());
        EVLOG_warning << "X509_verify_cert failed at depth " << depth;

        // Log the certificate at the error depth
        X509* err_cert = X509_STORE_CTX_get_current_cert(store_ctx_ptr.get());
        if (err_cert != nullptr) {
            char err_subject[256] = {};
            X509_NAME_oneline(X509_get_subject_name(err_cert), err_subject, sizeof(err_subject));
            EVLOG_warning << "  Failing certificate: " << err_subject;
        }

        return to_certificate_error(ec);
    }

    EVLOG_info << "Certificate chain verification: PASSED";
    return CertificateValidationResult::Valid;
}

KeyValidationResult OpenSSLSupplier::x509_check_private_key(X509Handle* handle, std::string private_key,
                                                            std::optional<std::string> password) {
    const X509* x509 = get(handle);

    if (x509 == nullptr) {
        return KeyValidationResult::Unknown;
    }

    {
        const OpenSSLProvider provider; // ensure providers are loaded
                                        // minimise holding the mutex
    }

    const BIO_ptr bio(BIO_new_mem_buf(private_key.c_str(), -1));
    // Passing password string since if NULL is provided, the password CB will be called
    const EVP_PKEY_ptr evp_pkey(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, (void*)password.value_or("").c_str()));

    const bool bResult = true;
    if (!evp_pkey) {
        EVLOG_warning << "Invalid evp_pkey: " << private_key << " error: " << ERR_error_string(ERR_get_error(), nullptr)
                      << " Password configured correctly?";
        ERR_print_errors_fp(stderr);

        return KeyValidationResult::KeyLoadFailure;
    }

    KeyValidationResult result = KeyValidationResult::Unknown;

    if (X509_check_private_key(x509, evp_pkey.get()) == 1) {
        result = KeyValidationResult::Valid;
    } else {
        result = KeyValidationResult::Invalid;
    }

    return result;
}

bool OpenSSLSupplier::x509_verify_signature(X509Handle* handle, const std::vector<std::uint8_t>& signature,
                                            const std::vector<std::uint8_t>& data) {
    {
        const OpenSSLProvider provider; // ensure providers are loaded
                                        // minimise holding the mutex
    }

    // extract public key
    X509* x509 = get(handle);

    if (x509 == nullptr) {
        return false;
    }

    const EVP_PKEY_ptr public_key_ptr(X509_get_pubkey(x509));

    if (public_key_ptr.get() == nullptr) {
        EVLOG_error << "Error during X509_get_pubkey";
        return false;
    }

    // verify file signature
    const EVP_PKEY_CTX_ptr public_key_context_ptr(EVP_PKEY_CTX_new(public_key_ptr.get(), nullptr));

    if (public_key_context_ptr.get() == nullptr) {
        EVLOG_error << "Error setting up public key context";
        return false;
    }

    if (EVP_PKEY_verify_init(public_key_context_ptr.get()) <= 0) {
        EVLOG_error << "Error during EVP_PKEY_verify_init";
        return false;
    }

    if (EVP_PKEY_CTX_set_signature_md(public_key_context_ptr.get(), EVP_sha256()) <= 0) {
        EVLOG_error << "Error during EVP_PKEY_CTX_set_signature_md";
        return false;
    };

    const int result =
        EVP_PKEY_verify(public_key_context_ptr.get(),
                        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
                        reinterpret_cast<const unsigned char*>(signature.data()), signature.size(),
                        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
                        reinterpret_cast<const unsigned char*>(data.data()), data.size());

    EVP_cleanup();

    if (result != 1) {
        EVLOG_error << "Failure to verify: " << result;
        return false;
    }
    EVLOG_debug << "Successful verification";
    return true;
}

CertificateSignRequestResult OpenSSLSupplier::x509_generate_csr(const CertificateSigningRequestInfo& csr_info,
                                                                std::string& out_csr) {

    KeyHandle_ptr gen_key;
    EVP_PKEY_CTX_ptr ctx;

    if (false == s_generate_key(csr_info.key_info, gen_key, ctx)) {
        return CertificateSignRequestResult::KeyGenerationError;
    }

    EVP_PKEY* key = get(gen_key.get());

    // If the key is an EC key with explicit curve parameters (as exported by the OP-TEE
    // PKCS#11 TA), we need to reconstruct a public-key-only EVP_PKEY using the named curve
    // OID for the CSR's SubjectPublicKeyInfo. Explicit parameters produce ~335 bytes of DER
    // encoding (vs ~91 for named curve) and cause OpenSSL 3.x to reject the signed certificate
    // with X509_V_ERR_EC_KEY_EXPLICIT_PARAMS (error 94).
    //
    // The converted key is used only for X509_REQ_set_pubkey() — the original HSM-backed key
    // is still used for X509_REQ_sign() since only it has access to the private key material.
    EVP_PKEY* pubkey_for_csr = key;
    EVP_PKEY_ptr named_curve_pubkey(nullptr);

    if (EVP_PKEY_id(key) == EVP_PKEY_EC) {
        int der_len = i2d_PUBKEY(key, nullptr);
        if (der_len > 100) {
            // DER encoding is too large for a named-curve key — explicit parameters detected.
            // Attempt to reconstruct with named curve encoding.
            EVLOG_info << "EC key has explicit parameters (DER size: " << der_len
                       << " bytes), converting to named curve for CSR";

            char group_name[64] = {};
            size_t group_name_len = 0;
            bool have_group = EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group_name,
                                                              sizeof(group_name), &group_name_len);
            if (!have_group) {
                EVLOG_warning << "Could not retrieve EC curve name — CSR will use explicit parameters";
                ERR_clear_error();
            } else {
                // The pkcs11 provider won't export the raw EC point via OSSL_PKEY_PARAM_PUB_KEY.
                // Instead, we serialize the public key to DER (which i2d_PUBKEY supports even for
                // pkcs11 keys), then decode it back into a software (default provider) EVP_PKEY.
                // From the software key we can extract the EC point, then reconstruct a new key
                // with named curve encoding.

                // Step 1: Serialize the pkcs11 key's public part to DER
                unsigned char* der_buf = nullptr;
                int der_size = i2d_PUBKEY(key, &der_buf);
                if (der_size <= 0 || der_buf == nullptr) {
                    EVLOG_warning << "Could not serialize EC public key to DER — CSR will use explicit parameters";
                    ERR_print_errors_fp(stderr);
                } else {
                    // Step 2: Decode DER back into a software EVP_PKEY (default provider)
                    const unsigned char* der_ptr = der_buf;
                    EVP_PKEY* sw_pubkey = d2i_PUBKEY(nullptr, &der_ptr, der_size);
                    OPENSSL_free(der_buf);

                    if (sw_pubkey == nullptr) {
                        EVLOG_warning << "Could not decode EC public key DER — CSR will use explicit parameters";
                        ERR_print_errors_fp(stderr);
                    } else {
                        // Step 3: Extract the raw EC point from the software key
                        size_t point_len = 0;
                        EVP_PKEY_get_octet_string_param(sw_pubkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &point_len);
                        std::vector<unsigned char> point(point_len);

                        if (point_len > 0 &&
                            EVP_PKEY_get_octet_string_param(sw_pubkey, OSSL_PKEY_PARAM_PUB_KEY, point.data(),
                                                             point.size(), &point_len)) {
                            // Step 4: Reconstruct a public-key-only EVP_PKEY with named curve encoding
                            OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
                            OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
                            OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point_len);
                            OSSL_PARAM* fromdata_params = OSSL_PARAM_BLD_to_param(bld);

                            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
                            if (pctx != nullptr && EVP_PKEY_fromdata_init(pctx) > 0) {
                                EVP_PKEY* new_pubkey = nullptr;
                                if (EVP_PKEY_fromdata(pctx, &new_pubkey, EVP_PKEY_PUBLIC_KEY, fromdata_params) > 0) {
                                    named_curve_pubkey = EVP_PKEY_ptr(new_pubkey);
                                    pubkey_for_csr = named_curve_pubkey.get();

                                    int new_der_len = i2d_PUBKEY(pubkey_for_csr, nullptr);
                                    EVLOG_info << "Converted EC public key to named curve '" << group_name
                                               << "' (DER size: " << new_der_len << " bytes)";
                                } else {
                                    EVLOG_warning << "EVP_PKEY_fromdata failed — CSR will use explicit parameters";
                                    ERR_print_errors_fp(stderr);
                                }
                            } else {
                                EVLOG_warning << "EVP_PKEY_CTX setup failed — CSR will use explicit parameters";
                                ERR_print_errors_fp(stderr);
                            }

                            EVP_PKEY_CTX_free(pctx);
                            OSSL_PARAM_free(fromdata_params);
                            OSSL_PARAM_BLD_free(bld);
                        } else {
                            EVLOG_warning << "Could not extract EC point from software key — "
                                          << "CSR will use explicit parameters";
                            ERR_print_errors_fp(stderr);
                        }

                        EVP_PKEY_free(sw_pubkey);
                    }
                }
            }
        }
    }

    // X509 CSR request
    const X509_REQ_ptr x509_req_ptr(X509_REQ_new());

    if (nullptr == x509_req_ptr.get()) {
        EVLOG_error << "Failed to create CSR request!";
        ERR_print_errors_fp(stderr);

        return CertificateSignRequestResult::Unknown;
    }

    // set version of x509 req
    const int n_version = csr_info.n_version;

    if (0 == X509_REQ_set_version(x509_req_ptr.get(), n_version)) {
        EVLOG_error << "Failed to set csr version!";
        ERR_print_errors_fp(stderr);

        return CertificateSignRequestResult::VersioningError;
    }

    // set public key of x509 req — use the named-curve key if we converted, otherwise original
    if (0 == X509_REQ_set_pubkey(x509_req_ptr.get(), pubkey_for_csr)) {
        EVLOG_error << "Failed to set csr pubkey!";
        ERR_print_errors_fp(stderr);

        return CertificateSignRequestResult::PubkeyError;
    }

    X509_NAME* x509Name = X509_REQ_get_subject_name(x509_req_ptr.get());

    // set subject of x509 req
    X509_NAME_add_entry_by_txt(
        x509Name, "C", MBSTRING_ASC,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
        reinterpret_cast<const unsigned char*>(csr_info.country.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(
        x509Name, "O", MBSTRING_ASC,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
        reinterpret_cast<const unsigned char*>(csr_info.organization.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(
        x509Name, "CN", MBSTRING_ASC,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
        reinterpret_cast<const unsigned char*>(csr_info.commonName.c_str()), -1, -1, 0);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
    X509_NAME_add_entry_by_txt(x509Name, "DC", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("CPO"), -1, -1, 0);

    STACK_OF(X509_EXTENSION)* extensions = sk_X509_EXTENSION_new_null();
    X509_EXTENSION* ext_key_usage =
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, "digitalSignature, keyAgreement");
    X509_EXTENSION* ext_basic_constraints =
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:false");
    sk_X509_EXTENSION_push(extensions, ext_key_usage);
    sk_X509_EXTENSION_push(extensions, ext_basic_constraints);

    std::vector<std::string> names;
    if (csr_info.dns_name.has_value()) {
        names.push_back({std::string("DNS:") + csr_info.dns_name.value()});
    }
    if (csr_info.ip_address.has_value()) {
        names.push_back({std::string("IP:") + csr_info.ip_address.value()});
    }

    X509_EXTENSION* ext_san = nullptr;
    if (!names.empty()) {
        auto comma_fold = [](std::string a, const std::string& b) { return std::move(a) + ',' + b; };
        const std::string value =
            std::accumulate(std::next(names.begin()), names.end(), std::string(names[0]), comma_fold);
        ext_san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, value.c_str());
        sk_X509_EXTENSION_push(extensions, ext_san);
    }

    const bool result = X509_REQ_add_extensions(x509_req_ptr.get(), extensions) != 0;
    X509_EXTENSION_free(ext_key_usage);
    X509_EXTENSION_free(ext_basic_constraints);
    X509_EXTENSION_free(ext_san);
    sk_X509_EXTENSION_free(extensions);

    if (!result) {
        EVLOG_error << "Failed to add csr extensions!";
        ERR_print_errors_fp(stderr);

        return CertificateSignRequestResult::ExtensionsError;
    }

    // sign the certificate with the private key
    const bool x509_signed = X509_REQ_sign(x509_req_ptr.get(), key, EVP_sha256()) != 0;

    if (x509_signed == false) {
        EVLOG_error << "Failed to sign csr with error!";
        ERR_print_errors_fp(stderr);

        return CertificateSignRequestResult::SigningError;
    }

    // write csr
    const BIO_ptr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509_REQ(bio.get(), x509_req_ptr.get());

    const BUF_MEM* mem_csr = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem_csr);

    out_csr = std::string(mem_csr->data, mem_csr->length);

    return CertificateSignRequestResult::Valid;
}

bool OpenSSLSupplier::digest_file_sha256(const fs::path& path, std::vector<std::uint8_t>& out_digest) {
    EVP_MD_CTX_ptr md_context_ptr(EVP_MD_CTX_create());
    if (md_context_ptr.get() == nullptr) {
        EVLOG_error << "Could not create EVP_MD_CTX";
        return false;
    }

    const EVP_MD* md = EVP_get_digestbyname("SHA256");
    if (EVP_DigestInit_ex(md_context_ptr.get(), md, nullptr) == 0) {
        EVLOG_error << "Error during EVP_DigestInit_ex";
        return false;
    }

    bool digest_error = false;

    unsigned int sha256_out_length = 0;
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> sha256_out;

    // calculate sha256 of file
    const bool processed_file = filesystem_utils::process_file(
        path, BUFSIZ, [&](const std::uint8_t* bytes, std::size_t read, bool last_chunk) -> bool {
            if (read > 0) {
                if (EVP_DigestUpdate(md_context_ptr.get(), bytes, read) == 0) {
                    EVLOG_error << "Error during EVP_DigestUpdate";
                    digest_error = true;
                    return true;
                }
            }

            if (last_chunk) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
                if (EVP_DigestFinal_ex(md_context_ptr.get(), reinterpret_cast<unsigned char*>(sha256_out.data()),
                                       &sha256_out_length) == 0) {
                    EVLOG_error << "Error during EVP_DigestFinal_ex";
                    digest_error = true;
                    return true;
                }
            }

            return false;
        });

    if ((processed_file == false) || (digest_error == true)) {
        EVLOG_error << "Could not digest file at: " << path.string();
        return false;
    }

    out_digest.clear();
    std::copy_n(sha256_out.begin(), sha256_out_length, std::back_inserter((out_digest)));

    return true;
}

namespace {
template <typename T> bool base64_decode(const std::string& base64_string, T& out_decoded) {
    const EVP_ENCODE_CTX_ptr base64_decode_context_ptr(EVP_ENCODE_CTX_new());
    if (!base64_decode_context_ptr.get()) {
        EVLOG_error << "Error during EVP_ENCODE_CTX_new";
        return false;
    }

    EVP_DecodeInit(base64_decode_context_ptr.get());
    if (!base64_decode_context_ptr.get()) {
        EVLOG_error << "Error during EVP_DecodeInit";
        return false;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
    const auto* encoded_str = reinterpret_cast<const unsigned char*>(base64_string.data());
    const int base64_length = base64_string.size();

    std::vector<std::uint8_t> decoded_out;
    decoded_out.reserve(base64_length);

    int decoded_out_length = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
    if (EVP_DecodeUpdate(base64_decode_context_ptr.get(), reinterpret_cast<unsigned char*>(decoded_out.data()),
                         &decoded_out_length, encoded_str, base64_length) < 0) {
        EVLOG_error << "Error during DecodeUpdate";
        return false;
    }

    int decode_final_out = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
    if (EVP_DecodeFinal(base64_decode_context_ptr.get(), reinterpret_cast<unsigned char*>(decoded_out.data()),
                        &decode_final_out) < 0) {
        EVLOG_error << "Error during EVP_DecodeFinal";
        return false;
    }

    out_decoded.clear();
    std::copy_n(decoded_out.begin(), decoded_out_length, std::back_inserter((out_decoded)));

    return true;
}

bool base64_encode(const unsigned char* bytes_str, int bytes_size, std::string& out_encoded) {
    const EVP_ENCODE_CTX_ptr base64_encode_context_ptr(EVP_ENCODE_CTX_new());
    if (base64_encode_context_ptr.get() == nullptr) {
        EVLOG_error << "Error during EVP_ENCODE_CTX_new";
        return false;
    }

    EVP_EncodeInit(base64_encode_context_ptr.get());
    // evp_encode_ctx_set_flags(base64_encode_context_ptr.get(), EVP_ENCODE_CTX_NO_NEWLINES); // Of course it's not
    // public

    if (base64_encode_context_ptr.get() == nullptr) {
        EVLOG_error << "Error during EVP_EncodeInit";
        return false;
    }

    const int base64_length = ((bytes_size / 3) * 4) + 2;
    // If it causes issues, replace with 'alloca' on different platform
    std::vector<char> base64_out;
    base64_out.reserve(base64_length + 66); // + 66 bytes for final block
    int full_len = 0;

    int base64_out_length = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
    if (EVP_EncodeUpdate(base64_encode_context_ptr.get(), reinterpret_cast<unsigned char*>(base64_out.data()),
                         &base64_out_length, bytes_str, bytes_size) < 0) {
        EVLOG_error << "Error during EVP_EncodeUpdate";
        return false;
    }
    full_len += base64_out_length;

    EVP_EncodeFinal(base64_encode_context_ptr.get(),
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed because of OpenSSL API
                    std::next(reinterpret_cast<unsigned char*>(base64_out.data()), base64_out_length),
                    &base64_out_length);
    full_len += base64_out_length;

    out_encoded.assign(base64_out.data(), full_len);

    return true;
}
} // namespace

bool OpenSSLSupplier::base64_decode_to_bytes(const std::string& base64_string, std::vector<std::uint8_t>& out_decoded) {
    return base64_decode<std::vector<std::uint8_t>>(base64_string, out_decoded);
}

bool OpenSSLSupplier::base64_decode_to_string(const std::string& base64_string, std::string& out_decoded) {
    return base64_decode<std::string>(base64_string, out_decoded);
}

bool OpenSSLSupplier::base64_encode_from_bytes(const std::vector<std::uint8_t>& bytes, std::string& out_encoded) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed for API usage
    return base64_encode(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), out_encoded);
}

bool OpenSSLSupplier::base64_encode_from_string(const std::string& string, std::string& out_encoded) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): needed for API usage
    return base64_encode(reinterpret_cast<const unsigned char*>(string.data()), string.size(), out_encoded);
}

} // namespace evse_security

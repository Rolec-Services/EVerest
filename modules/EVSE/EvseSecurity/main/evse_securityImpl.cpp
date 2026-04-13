// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include "evse_securityImpl.hpp"
#include <everest/conversions/evse_security/conversions.hpp>

#include <evse_security/crypto/openssl/openssl_pkcs11_helper.hpp>

#include <filesystem>
#include <fstream>

namespace module {
namespace main {

void evse_securityImpl::init() {

    const auto certs_path = this->mod->info.paths.etc / "certs";
    evse_security::FilePaths file_paths = {certs_path / this->mod->config.csms_ca_bundle,
                                           certs_path / this->mod->config.mf_ca_bundle,
                                           certs_path / this->mod->config.mo_ca_bundle,
                                           certs_path / this->mod->config.v2g_ca_bundle,
                                           certs_path / this->mod->config.csms_leaf_cert_directory,
                                           certs_path / this->mod->config.csms_leaf_key_directory,
                                           certs_path / this->mod->config.secc_leaf_cert_directory,
                                           certs_path / this->mod->config.secc_leaf_key_directory};

    std::optional<std::string> private_key_password = std::nullopt;
    if (!this->mod->config.private_key_password.empty()) {
        private_key_password = this->mod->config.private_key_password;
    }

    // Configure certificate store limits
    std::optional<std::uintmax_t> max_fs_usage_bytes = std::nullopt; // No filesystem size limit
    std::optional<std::uintmax_t> max_certificate_entries = std::nullopt;
    if (this->mod->config.max_certificate_entries > 0) {
        max_certificate_entries = static_cast<std::uintmax_t>(this->mod->config.max_certificate_entries);
    }
    std::optional<std::uintmax_t> max_hsm_key_entries = std::nullopt;
    if (this->mod->config.max_hsm_key_entries > 0) {
        max_hsm_key_entries = static_cast<std::uintmax_t>(this->mod->config.max_hsm_key_entries);
    }

    // Configure the PKCS#11 helper BEFORE constructing EvseSecurity, because the
    // constructor calls delete_hsm_orphaned_keys() which needs a valid PKCS#11 config.
    evse_security::PKCS11Config pkcs11_config;
    pkcs11_config.module_path = this->mod->config.pkcs11_module_path;
    pkcs11_config.slot = this->mod->config.pkcs11_slot;
    pkcs11_config.token = this->mod->config.pkcs11_token;
    pkcs11_config.pin = this->mod->config.pkcs11_pin;
    evse_security::PKCS11Helper::set_config(pkcs11_config);

    // Ensure the configured HSM token exists and is initialised. Only runs when a PKCS#11
    // module path has been configured (i.e. HSM is in use). This must happen before
    // EvseSecurity construction (which runs orphan cleanup at startup).
    // Throws std::runtime_error on failure — EVerest will not start without a working HSM token.
    if (!pkcs11_config.module_path.empty()) {
        evse_security::PKCS11Helper::ensure_token_initialised();

        // Sync the PIN to the OpenSSL pkcs11-provider PIN file (configured in openssl.cnf as
        // pkcs11-module-token-pin = file:/etc/pki/pin.txt). Without this, if the file is stale
        // or missing, the provider falls back to prompting stdin — which stalls EVerest.
        // ensure_token_initialised() has already verified the PIN is correct via C_Login before
        // we reach this point, so it is safe to write.
        static const std::string pkcs11_pin_file = "/etc/pki/pin.txt";
        {
            std::ofstream pin_file(pkcs11_pin_file, std::ios::trunc);
            if (!pin_file) {
                throw std::runtime_error("Failed to open PKCS#11 PIN file for writing: " + pkcs11_pin_file);
            }
            pin_file << pkcs11_config.pin;
            if (!pin_file) {
                throw std::runtime_error("Failed to write PKCS#11 PIN file: " + pkcs11_pin_file);
            }
        }
        std::filesystem::permissions(pkcs11_pin_file,
                                     std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace);
    }

    this->evse_security = std::make_unique<evse_security::EvseSecurity>(file_paths, private_key_password,
                                                                        max_fs_usage_bytes, max_certificate_entries,
                                                                        std::nullopt, std::nullopt, max_hsm_key_entries);
}

void evse_securityImpl::ready() {
}

types::evse_security::InstallCertificateResult
evse_securityImpl::handle_install_ca_certificate(std::string& certificate,
                                                 types::evse_security::CaCertificateType& certificate_type) {
    try {
        const auto response = conversions::to_everest(
            this->evse_security->install_ca_certificate(certificate, conversions::from_everest(certificate_type)));
        if (response == types::evse_security::InstallCertificateResult::Accepted) {
            types::evse_security::CertificateStoreUpdate update;
            update.operation = types::evse_security::CertificateStoreUpdateOperation::Installed;
            update.ca_certificate_type = certificate_type;
            this->publish_certificate_store_update(update);
        }
        return response;
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return types::evse_security::InstallCertificateResult::WriteError;
    }
}

types::evse_security::DeleteCertificateResult
evse_securityImpl::handle_delete_certificate(types::evse_security::CertificateHashData& certificate_hash_data) {
    try {
        const auto response = this->evse_security->delete_certificate(conversions::from_everest(certificate_hash_data));
        const auto result = conversions::to_everest(response.result);

        if (result == types::evse_security::DeleteCertificateResult::Accepted) {
            types::evse_security::CertificateStoreUpdate update;

            update.operation = types::evse_security::CertificateStoreUpdateOperation::Deleted;

            if (response.ca_certificate_type.has_value()) {
                update.ca_certificate_type = conversions::to_everest(response.ca_certificate_type.value());
            }
            if (response.leaf_certificate_type.has_value()) {
                update.leaf_certificate_type = conversions::to_everest(response.leaf_certificate_type.value());
            }

            this->publish_certificate_store_update(update);
        }

        return result;
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return types::evse_security::DeleteCertificateResult::Failed;
    }
}

types::evse_security::InstallCertificateResult
evse_securityImpl::handle_update_leaf_certificate(std::string& certificate_chain,
                                                  types::evse_security::LeafCertificateType& certificate_type) {
    try {
        const auto response = conversions::to_everest(this->evse_security->update_leaf_certificate(
            certificate_chain, conversions::from_everest(certificate_type)));
        if (response == types::evse_security::InstallCertificateResult::Accepted) {
            types::evse_security::CertificateStoreUpdate update;
            update.operation = types::evse_security::CertificateStoreUpdateOperation::Installed;
            update.leaf_certificate_type = certificate_type;
            this->publish_certificate_store_update(update);
        }
        return response;
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return types::evse_security::InstallCertificateResult::WriteError;
    }
}

types::evse_security::CertificateValidationResult evse_securityImpl::handle_verify_certificate(
    std::string& certificate_chain, std::vector<types::evse_security::LeafCertificateType>& certificate_types) {

    std::vector<evse_security::LeafCertificateType> _certificate_types;

    for (const auto& certificate_type : certificate_types) {
        try {
            _certificate_types.push_back(conversions::from_everest(certificate_type));
        } catch (const std::out_of_range& e) {
            EVLOG_warning << e.what();
        }
    }

    try {
        return conversions::to_everest(this->evse_security->verify_certificate(certificate_chain, _certificate_types));
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return types::evse_security::CertificateValidationResult::Unknown;
    }
}

types::evse_security::GetInstalledCertificatesResult evse_securityImpl::handle_get_installed_certificates(
    std::vector<types::evse_security::CertificateType>& certificate_types) {
    std::vector<evse_security::CertificateType> _certificate_types;

    for (const auto& certificate_type : certificate_types) {
        try {
            _certificate_types.push_back(conversions::from_everest(certificate_type));
        } catch (const std::out_of_range& e) {
            EVLOG_warning << e.what();
        }
    }

    try {
        return conversions::to_everest(this->evse_security->get_installed_certificates(_certificate_types));
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return {types::evse_security::GetInstalledCertificatesStatus::NotFound, {}};
    }
}

types::evse_security::OCSPRequestDataList evse_securityImpl::handle_get_v2g_ocsp_request_data() {
    try {
        return conversions::to_everest(this->evse_security->get_v2g_ocsp_request_data());
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return {};
    }
}

types::evse_security::OCSPRequestDataList
evse_securityImpl::handle_get_mo_ocsp_request_data(std::string& certificate_chain) {
    try {
        return conversions::to_everest(this->evse_security->get_mo_ocsp_request_data(certificate_chain));
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return {};
    }
}

void evse_securityImpl::handle_update_ocsp_cache(types::evse_security::CertificateHashData& certificate_hash_data,
                                                 std::string& ocsp_response) {
    try {
        this->evse_security->update_ocsp_cache(conversions::from_everest(certificate_hash_data), ocsp_response);
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
    }
}

bool evse_securityImpl::handle_is_ca_certificate_installed(types::evse_security::CaCertificateType& certificate_type) {
    try {
        return this->evse_security->is_ca_certificate_installed(conversions::from_everest(certificate_type));
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return false;
    }
}

types::evse_security::GetCertificateSignRequestResult evse_securityImpl::handle_generate_certificate_signing_request(
    types::evse_security::LeafCertificateType& certificate_type, std::string& country, std::string& organization,
    std::string& common, bool& use_tpm) {
    types::evse_security::GetCertificateSignRequestResult response;

    try {
        auto csr_response = this->evse_security->generate_certificate_signing_request(
            conversions::from_everest(certificate_type), country, organization, common, use_tpm);

        response.status = conversions::to_everest(csr_response.status);

        if (csr_response.status == evse_security::GetCertificateSignRequestStatus::Accepted &&
            csr_response.csr.has_value()) {
            response.csr = csr_response.csr;
        }

        return response;
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        response.status = types::evse_security::GetCertificateSignRequestStatus::GenerationError;
        return response;
    }
}

types::evse_security::GetCertificateInfoResult
evse_securityImpl::handle_get_leaf_certificate_info(types::evse_security::LeafCertificateType& certificate_type,
                                                    types::evse_security::EncodingFormat& encoding,
                                                    bool& include_ocsp) {
    types::evse_security::GetCertificateInfoResult response;

    try {
        const auto leaf_info = this->evse_security->get_leaf_certificate_info(
            conversions::from_everest(certificate_type), conversions::from_everest(encoding), include_ocsp);

        response.status = conversions::to_everest(leaf_info.status);

        if (leaf_info.status == evse_security::GetCertificateInfoStatus::Accepted && leaf_info.info.has_value()) {
            response.info = conversions::to_everest(leaf_info.info.value());
        }

        return response;
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        response.status = types::evse_security::GetCertificateInfoStatus::Rejected;
        return response;
    }
}

types::evse_security::GetCertificateFullInfoResult
evse_securityImpl::handle_get_all_valid_certificates_info(types::evse_security::LeafCertificateType& certificate_type,
                                                          types::evse_security::EncodingFormat& encoding,
                                                          bool& include_ocsp) {
    types::evse_security::GetCertificateFullInfoResult response;

    try {
        const auto full_leaf_info = this->evse_security->get_all_valid_certificates_info(
            conversions::from_everest(certificate_type), conversions::from_everest(encoding), include_ocsp);

        response.status = conversions::to_everest(full_leaf_info.status);

        if (full_leaf_info.status == evse_security::GetCertificateInfoStatus::Accepted) {
            for (const auto& info : full_leaf_info.info) {
                response.info.push_back(conversions::to_everest(info));
            }
        }

        return response;
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        response.status = types::evse_security::GetCertificateInfoStatus::Rejected;
        return response;
    }
}

std::string evse_securityImpl::handle_get_verify_file(types::evse_security::CaCertificateType& certificate_type) {
    try {
        return this->evse_security->get_verify_file(conversions::from_everest(certificate_type));
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return {};
    }
}

std::string evse_securityImpl::handle_get_verify_location(types::evse_security::CaCertificateType& certificate_type) {
    try {
        return this->evse_security->get_verify_location(conversions::from_everest(certificate_type));
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return {};
    }
}

int evse_securityImpl::handle_get_leaf_expiry_days_count(types::evse_security::LeafCertificateType& certificate_type) {
    try {
        return this->evse_security->get_leaf_expiry_days_count(conversions::from_everest(certificate_type));
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return 0;
    }
}

bool evse_securityImpl::handle_verify_file_signature(std::string& file_path, std::string& signing_certificate,
                                                     std::string& signature) {
    try {
        return evse_security::EvseSecurity::verify_file_signature(std::filesystem::path(file_path), signing_certificate,
                                                                  signature);
    } catch (const std::out_of_range& e) {
        EVLOG_warning << e.what();
        return false;
    }
}

} // namespace main
} // namespace module

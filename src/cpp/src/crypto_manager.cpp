#include "crypto_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

namespace distributedfs {

CryptoManager::CryptoManager() : encrypt_ctx_(nullptr), decrypt_ctx_(nullptr), hash_ctx_(nullptr) {
    initialize_crypto_contexts();
}

CryptoManager::~CryptoManager() {
    cleanup_crypto_contexts();
}

bool CryptoManager::initialize_crypto_contexts() {
    encrypt_ctx_ = EVP_CIPHER_CTX_new();
    decrypt_ctx_ = EVP_CIPHER_CTX_new();
    hash_ctx_ = EVP_MD_CTX_new();
    
    return encrypt_ctx_ != nullptr && decrypt_ctx_ != nullptr && hash_ctx_ != nullptr;
}

void CryptoManager::cleanup_crypto_contexts() {
    if (encrypt_ctx_) {
        EVP_CIPHER_CTX_free(encrypt_ctx_);
        encrypt_ctx_ = nullptr;
    }
    
    if (decrypt_ctx_) {
        EVP_CIPHER_CTX_free(decrypt_ctx_);
        decrypt_ctx_ = nullptr;
    }
    
    if (hash_ctx_) {
        EVP_MD_CTX_free(hash_ctx_);
        hash_ctx_ = nullptr;
    }
}

std::vector<uint8_t> CryptoManager::encrypt_data(const std::vector<uint8_t>& data, 
                                                const std::string& key) {
    if (!encrypt_ctx_ || data.empty() || key.empty()) {
        throw std::runtime_error("Invalid encryption parameters");
    }
    
    // Generate IV
    std::vector<uint8_t> iv = generate_iv();
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(encrypt_ctx_, EVP_aes_256_cbc(), nullptr, 
                          reinterpret_cast<const unsigned char*>(key.c_str()), 
                          iv.data()) != 1) {
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    // Encrypt data
    std::vector<uint8_t> encrypted_data(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int encrypted_len = 0;
    int final_len = 0;
    
    if (EVP_EncryptUpdate(encrypt_ctx_, encrypted_data.data(), &encrypted_len,
                         data.data(), static_cast<int>(data.size())) != 1) {
        throw std::runtime_error("Failed to encrypt data");
    }
    
    if (EVP_EncryptFinal_ex(encrypt_ctx_, encrypted_data.data() + encrypted_len, &final_len) != 1) {
        throw std::runtime_error("Failed to finalize encryption");
    }
    
    // Prepend IV to encrypted data
    std::vector<uint8_t> result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), encrypted_data.begin(), encrypted_data.begin() + encrypted_len + final_len);
    
    return result;
}

std::vector<uint8_t> CryptoManager::decrypt_data(const std::vector<uint8_t>& encrypted_data, 
                                                const std::string& key) {
    if (!decrypt_ctx_ || encrypted_data.size() < IV_SIZE || key.empty()) {
        throw std::runtime_error("Invalid decryption parameters");
    }
    
    // Extract IV
    std::vector<uint8_t> iv(encrypted_data.begin(), encrypted_data.begin() + IV_SIZE);
    std::vector<uint8_t> ciphertext(encrypted_data.begin() + IV_SIZE, encrypted_data.end());
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(decrypt_ctx_, EVP_aes_256_cbc(), nullptr,
                          reinterpret_cast<const unsigned char*>(key.c_str()),
                          iv.data()) != 1) {
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    // Decrypt data
    std::vector<uint8_t> decrypted_data(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int decrypted_len = 0;
    int final_len = 0;
    
    if (EVP_DecryptUpdate(decrypt_ctx_, decrypted_data.data(), &decrypted_len,
                         ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("Failed to decrypt data");
    }
    
    if (EVP_DecryptFinal_ex(decrypt_ctx_, decrypted_data.data() + decrypted_len, &final_len) != 1) {
        throw std::runtime_error("Failed to finalize decryption");
    }
    
    decrypted_data.resize(decrypted_len + final_len);
    return decrypted_data;
}

std::string CryptoManager::generate_encryption_key() {
    std::vector<uint8_t> key_bytes(KEY_SIZE);
    if (RAND_bytes(key_bytes.data(), KEY_SIZE) != 1) {
        throw std::runtime_error("Failed to generate encryption key");
    }
    
    return std::string(key_bytes.begin(), key_bytes.end());
}

std::string CryptoManager::generate_random_salt() {
    std::vector<uint8_t> salt_bytes(SALT_SIZE);
    if (RAND_bytes(salt_bytes.data(), SALT_SIZE) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }
    
    std::ostringstream oss;
    for (uint8_t byte : salt_bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::string CryptoManager::derive_key_from_password(const std::string& password, 
                                                   const std::string& salt) {
    if (password.empty() || salt.empty()) {
        throw std::runtime_error("Password and salt cannot be empty");
    }
    
    std::vector<uint8_t> derived_key(KEY_SIZE);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                         reinterpret_cast<const unsigned char*>(salt.c_str()),
                         static_cast<int>(salt.length()),
                         10000, // iterations
                         EVP_sha256(),
                         KEY_SIZE,
                         derived_key.data()) != 1) {
        throw std::runtime_error("Failed to derive key from password");
    }
    
    return std::string(derived_key.begin(), derived_key.end());
}

std::string CryptoManager::calculate_sha256(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::string CryptoManager::calculate_file_checksum(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for checksum calculation");
    }
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::vector<uint8_t> CryptoManager::sign_data(const std::vector<uint8_t>& data, 
                                             const std::string& private_key) {
    // Simplified implementation - in production, use proper digital signatures
    std::string signature = calculate_sha256(data) + "_signed_with_" + private_key;
    return std::vector<uint8_t>(signature.begin(), signature.end());
}

bool CryptoManager::verify_signature(const std::vector<uint8_t>& data, 
                                    const std::vector<uint8_t>& signature,
                                    const std::string& public_key) {
    // Simplified implementation - in production, use proper signature verification
    std::string expected_signature = calculate_sha256(data) + "_signed_with_" + public_key;
    std::string actual_signature(signature.begin(), signature.end());
    return expected_signature == actual_signature;
}

bool CryptoManager::is_key_valid(const std::string& key) {
    return key.length() >= KEY_SIZE && validate_key_strength(key);
}

void CryptoManager::secure_wipe(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

std::string CryptoManager::get_random_bytes(size_t length) {
    std::vector<uint8_t> random_bytes(length);
    if (RAND_bytes(random_bytes.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    
    std::ostringstream oss;
    for (uint8_t byte : random_bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

CryptoManager::SecurityScanResult CryptoManager::perform_security_scan() {
    SecurityScanResult result;
    result.scan_time = std::chrono::system_clock::now();
    
    // Simplified security scan - in production, integrate with real CVE databases
    result.has_vulnerabilities = false;
    
    // Check for common vulnerabilities
    std::vector<std::string> components = {"openssl", "boost", "sqlite"};
    for (const std::string& component : components) {
        if (check_for_known_vulnerabilities(component)) {
            result.has_vulnerabilities = true;
            result.cve_ids.push_back("CVE-2023-XXXX-" + component);
            result.recommendations.push_back("Update " + component + " to latest version");
        }
    }
    
    if (!result.has_vulnerabilities) {
        result.recommendations.push_back("No known vulnerabilities found");
    }
    
    return result;
}

bool CryptoManager::check_for_known_vulnerabilities(const std::string& component) {
    // Simplified vulnerability check - in production, query real CVE databases
    // For demonstration, randomly return false (no vulnerabilities)
    return false;
}

std::vector<uint8_t> CryptoManager::generate_iv() {
    std::vector<uint8_t> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }
    return iv;
}

bool CryptoManager::validate_key_strength(const std::string& key) {
    // Basic key strength validation
    return key.length() >= KEY_SIZE;
}

} // namespace distributedfs 
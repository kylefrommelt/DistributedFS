#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace distributedfs {

class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();

    // Encryption/Decryption
    std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data, 
                                     const std::string& key);
    std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& encrypted_data, 
                                     const std::string& key);
    
    // Key management
    std::string generate_encryption_key();
    std::string generate_random_salt();
    std::string derive_key_from_password(const std::string& password, 
                                        const std::string& salt);
    
    // Hashing
    std::string calculate_sha256(const std::vector<uint8_t>& data);
    std::string calculate_file_checksum(const std::string& filepath);
    
    // Digital signatures
    std::vector<uint8_t> sign_data(const std::vector<uint8_t>& data, 
                                  const std::string& private_key);
    bool verify_signature(const std::vector<uint8_t>& data, 
                         const std::vector<uint8_t>& signature,
                         const std::string& public_key);
    
    // Security utilities
    bool is_key_valid(const std::string& key);
    void secure_wipe(std::vector<uint8_t>& data);
    std::string get_random_bytes(size_t length);
    
    // CVE and security scanning
    struct SecurityScanResult {
        bool has_vulnerabilities;
        std::vector<std::string> cve_ids;
        std::vector<std::string> recommendations;
        std::chrono::system_clock::time_point scan_time;
    };
    
    SecurityScanResult perform_security_scan();
    bool check_for_known_vulnerabilities(const std::string& component);

private:
    EVP_CIPHER_CTX* encrypt_ctx_;
    EVP_CIPHER_CTX* decrypt_ctx_;
    EVP_MD_CTX* hash_ctx_;
    
    // Security constants
    static constexpr size_t KEY_SIZE = 32; // AES-256
    static constexpr size_t IV_SIZE = 16;  // AES block size
    static constexpr size_t SALT_SIZE = 16;
    
    // Private helpers
    bool initialize_crypto_contexts();
    void cleanup_crypto_contexts();
    std::vector<uint8_t> generate_iv();
    bool validate_key_strength(const std::string& key);
};

} // namespace distributedfs 
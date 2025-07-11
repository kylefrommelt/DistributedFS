#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <future>
#include <chrono>
#include <shared_mutex>

namespace distributedfs {

struct FileMetadata {
    std::string file_id;
    std::string filename;
    size_t size;
    std::string checksum;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point modified_at;
    std::string encryption_key;
    std::vector<std::string> access_permissions;
};

class StorageEngine {
public:
    explicit StorageEngine(const std::string& storage_path);
    ~StorageEngine();

    // File operations
    std::future<std::string> store_file_async(const std::string& filename, 
                                             const std::vector<uint8_t>& data);
    std::future<std::vector<uint8_t>> retrieve_file_async(const std::string& file_id);
    std::future<bool> delete_file_async(const std::string& file_id);

    // Metadata operations
    std::shared_ptr<FileMetadata> get_file_metadata(const std::string& file_id);
    std::vector<std::shared_ptr<FileMetadata>> list_files();
    
    // System operations
    size_t get_total_storage_used() const;
    size_t get_file_count() const;
    bool is_healthy() const;

    // Configuration
    void set_max_file_size(size_t max_size);
    void set_storage_quota(size_t quota);
    void enable_compression(bool enabled);

private:
    std::string storage_path_;
    std::atomic<size_t> total_storage_used_;
    std::atomic<size_t> file_count_;
    std::atomic<size_t> max_file_size_;
    std::atomic<size_t> storage_quota_;
    std::atomic<bool> compression_enabled_;
    
    mutable std::shared_mutex metadata_mutex_;
    std::unordered_map<std::string, std::shared_ptr<FileMetadata>> file_metadata_;
    
    // Thread pool for async operations
    class ThreadPool;
    std::unique_ptr<ThreadPool> thread_pool_;
    
    // Private helpers
    std::string generate_file_id();
    std::string calculate_checksum(const std::vector<uint8_t>& data);
    bool validate_file_access(const std::string& file_id, const std::string& user_id);
    std::vector<uint8_t> compress_data(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decompress_data(const std::vector<uint8_t>& compressed_data);
    
    // Storage operations
    bool write_file_to_disk(const std::string& file_id, const std::vector<uint8_t>& data);
    std::vector<uint8_t> read_file_from_disk(const std::string& file_id);
    bool remove_file_from_disk(const std::string& file_id);
    
    // Metadata persistence
    void save_metadata();
    void load_metadata();
};

} // namespace distributedfs 
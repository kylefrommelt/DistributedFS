#include "storage_engine.h"
#include <fstream>
#include <filesystem>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <openssl/sha.h>

namespace distributedfs {

// Thread Pool Implementation
class StorageEngine::ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = std::thread::hardware_concurrency()) 
        : stop_(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            threads_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        condition_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        
                        if (stop_ && tasks_.empty()) {
                            return;
                        }
                        
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
        }
    }
    
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
        
        for (auto& thread : threads_) {
            thread.join();
        }
    }
    
    template<typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
        using return_type = typename std::result_of<F(Args...)>::type;
        
        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        
        std::future<return_type> result = task->get_future();
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) {
                throw std::runtime_error("ThreadPool is stopped");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        
        condition_.notify_one();
        return result;
    }

private:
    std::vector<std::thread> threads_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_;
};

StorageEngine::StorageEngine(const std::string& storage_path) 
    : storage_path_(storage_path)
    , total_storage_used_(0)
    , file_count_(0)
    , max_file_size_(1024 * 1024 * 1024) // 1GB default
    , storage_quota_(10ULL * 1024 * 1024 * 1024) // 10GB default
    , compression_enabled_(false)
    , thread_pool_(std::make_unique<ThreadPool>()) {
    
    // Create storage directory if it doesn't exist
    std::filesystem::create_directories(storage_path_);
    
    // Load existing metadata
    load_metadata();
}

StorageEngine::~StorageEngine() {
    save_metadata();
}

std::future<std::string> StorageEngine::store_file_async(const std::string& filename, 
                                                        const std::vector<uint8_t>& data) {
    return thread_pool_->enqueue([this, filename, data]() -> std::string {
        // Check quota
        if (total_storage_used_ + data.size() > storage_quota_) {
            throw std::runtime_error("Storage quota exceeded");
        }
        
        if (data.size() > max_file_size_) {
            throw std::runtime_error("File size exceeds maximum allowed size");
        }
        
        // Generate unique file ID
        std::string file_id = generate_file_id();
        
        // Create metadata
        auto metadata = std::make_shared<FileMetadata>();
        metadata->file_id = file_id;
        metadata->filename = filename;
        metadata->size = data.size();
        metadata->checksum = calculate_checksum(data);
        metadata->created_at = std::chrono::system_clock::now();
        metadata->modified_at = metadata->created_at;
        
        // Process data (compression if enabled)
        std::vector<uint8_t> processed_data = data;
        if (compression_enabled_) {
            processed_data = compress_data(data);
        }
        
        // Write to disk
        if (!write_file_to_disk(file_id, processed_data)) {
            throw std::runtime_error("Failed to write file to disk");
        }
        
        // Update metadata
        {
            std::unique_lock<std::shared_mutex> lock(metadata_mutex_);
            file_metadata_[file_id] = metadata;
        }
        
        // Update statistics
        total_storage_used_ += data.size();
        file_count_++;
        
        return file_id;
    });
}

std::future<std::vector<uint8_t>> StorageEngine::retrieve_file_async(const std::string& file_id) {
    return thread_pool_->enqueue([this, file_id]() -> std::vector<uint8_t> {
        // Check if file exists
        std::shared_ptr<FileMetadata> metadata;
        {
            std::shared_lock<std::shared_mutex> lock(metadata_mutex_);
            auto it = file_metadata_.find(file_id);
            if (it == file_metadata_.end()) {
                throw std::runtime_error("File not found");
            }
            metadata = it->second;
        }
        
        // Read from disk
        std::vector<uint8_t> data = read_file_from_disk(file_id);
        
        // Decompress if needed
        if (compression_enabled_) {
            data = decompress_data(data);
        }
        
        // Verify checksum
        if (calculate_checksum(data) != metadata->checksum) {
            throw std::runtime_error("File integrity check failed");
        }
        
        return data;
    });
}

std::future<bool> StorageEngine::delete_file_async(const std::string& file_id) {
    return thread_pool_->enqueue([this, file_id]() -> bool {
        // Check if file exists
        std::shared_ptr<FileMetadata> metadata;
        {
            std::shared_lock<std::shared_mutex> lock(metadata_mutex_);
            auto it = file_metadata_.find(file_id);
            if (it == file_metadata_.end()) {
                return false;
            }
            metadata = it->second;
        }
        
        // Remove from disk
        if (!remove_file_from_disk(file_id)) {
            return false;
        }
        
        // Remove from metadata
        {
            std::unique_lock<std::shared_mutex> lock(metadata_mutex_);
            file_metadata_.erase(file_id);
        }
        
        // Update statistics
        total_storage_used_ -= metadata->size;
        file_count_--;
        
        return true;
    });
}

std::shared_ptr<FileMetadata> StorageEngine::get_file_metadata(const std::string& file_id) {
    std::shared_lock<std::shared_mutex> lock(metadata_mutex_);
    auto it = file_metadata_.find(file_id);
    return (it != file_metadata_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<FileMetadata>> StorageEngine::list_files() {
    std::shared_lock<std::shared_mutex> lock(metadata_mutex_);
    std::vector<std::shared_ptr<FileMetadata>> files;
    files.reserve(file_metadata_.size());
    
    for (const auto& [file_id, metadata] : file_metadata_) {
        files.push_back(metadata);
    }
    
    return files;
}

size_t StorageEngine::get_total_storage_used() const {
    return total_storage_used_;
}

size_t StorageEngine::get_file_count() const {
    return file_count_;
}

bool StorageEngine::is_healthy() const {
    return std::filesystem::exists(storage_path_) && 
           std::filesystem::is_directory(storage_path_) &&
           total_storage_used_ <= storage_quota_;
}

void StorageEngine::set_max_file_size(size_t max_size) {
    max_file_size_ = max_size;
}

void StorageEngine::set_storage_quota(size_t quota) {
    storage_quota_ = quota;
}

void StorageEngine::enable_compression(bool enabled) {
    compression_enabled_ = enabled;
}

std::string StorageEngine::generate_file_id() {
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    return boost::uuids::to_string(uuid);
}

std::string StorageEngine::calculate_checksum(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::vector<uint8_t> StorageEngine::compress_data(const std::vector<uint8_t>& data) {
    // Simple compression placeholder - in production, use zlib or similar
    return data;
}

std::vector<uint8_t> StorageEngine::decompress_data(const std::vector<uint8_t>& compressed_data) {
    // Simple decompression placeholder - in production, use zlib or similar
    return compressed_data;
}

bool StorageEngine::write_file_to_disk(const std::string& file_id, const std::vector<uint8_t>& data) {
    std::string filepath = storage_path_ + "/" + file_id;
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

std::vector<uint8_t> StorageEngine::read_file_from_disk(const std::string& file_id) {
    std::string filepath = storage_path_ + "/" + file_id;
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for reading");
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    return data;
}

bool StorageEngine::remove_file_from_disk(const std::string& file_id) {
    std::string filepath = storage_path_ + "/" + file_id;
    return std::filesystem::remove(filepath);
}

void StorageEngine::save_metadata() {
    // Save metadata to JSON file - simplified implementation
    std::string metadata_file = storage_path_ + "/metadata.json";
    std::ofstream file(metadata_file);
    if (file.is_open()) {
        file << "{\n";
        file << "  \"total_storage_used\": " << total_storage_used_ << ",\n";
        file << "  \"file_count\": " << file_count_ << ",\n";
        file << "  \"files\": [\n";
        
        bool first = true;
        for (const auto& [file_id, metadata] : file_metadata_) {
            if (!first) file << ",\n";
            file << "    {\n";
            file << "      \"file_id\": \"" << metadata->file_id << "\",\n";
            file << "      \"filename\": \"" << metadata->filename << "\",\n";
            file << "      \"size\": " << metadata->size << ",\n";
            file << "      \"checksum\": \"" << metadata->checksum << "\"\n";
            file << "    }";
            first = false;
        }
        
        file << "\n  ]\n";
        file << "}\n";
    }
}

void StorageEngine::load_metadata() {
    // Load metadata from JSON file - simplified implementation
    std::string metadata_file = storage_path_ + "/metadata.json";
    if (std::filesystem::exists(metadata_file)) {
        // In a real implementation, would parse JSON properly
        // For now, just reset counters
        total_storage_used_ = 0;
        file_count_ = 0;
    }
}

} // namespace distributedfs 
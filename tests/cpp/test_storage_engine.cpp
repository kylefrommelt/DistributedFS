#include <cassert>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <thread>
#include "storage_engine.h"

using namespace distributedfs;

class TestRunner {
private:
    int tests_passed = 0;
    int tests_failed = 0;
    std::string test_storage_path = "/tmp/test_storage";

public:
    TestRunner() {
        // Clean up test directory
        if (std::filesystem::exists(test_storage_path)) {
            std::filesystem::remove_all(test_storage_path);
        }
        std::filesystem::create_directories(test_storage_path);
    }

    ~TestRunner() {
        // Clean up test directory
        if (std::filesystem::exists(test_storage_path)) {
            std::filesystem::remove_all(test_storage_path);
        }
    }

    void assert_true(bool condition, const std::string& test_name) {
        if (condition) {
            std::cout << "✓ " << test_name << " PASSED" << std::endl;
            tests_passed++;
        } else {
            std::cout << "✗ " << test_name << " FAILED" << std::endl;
            tests_failed++;
        }
    }

    void assert_equal(const std::string& expected, const std::string& actual, const std::string& test_name) {
        if (expected == actual) {
            std::cout << "✓ " << test_name << " PASSED" << std::endl;
            tests_passed++;
        } else {
            std::cout << "✗ " << test_name << " FAILED (expected: " << expected << ", actual: " << actual << ")" << std::endl;
            tests_failed++;
        }
    }

    void test_storage_engine_initialization() {
        std::cout << "\n=== Testing Storage Engine Initialization ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        assert_true(engine.is_healthy(), "Storage engine should be healthy after initialization");
        assert_true(engine.get_file_count() == 0, "File count should be 0 initially");
        assert_true(engine.get_total_storage_used() == 0, "Storage used should be 0 initially");
        assert_true(std::filesystem::exists(test_storage_path), "Storage directory should exist");
    }

    void test_file_storage_and_retrieval() {
        std::cout << "\n=== Testing File Storage and Retrieval ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        // Test data
        std::string filename = "test_file.txt";
        std::string content = "Hello, World! This is a test file.";
        std::vector<uint8_t> data(content.begin(), content.end());
        
        // Store file
        auto store_future = engine.store_file_async(filename, data);
        std::string file_id = store_future.get();
        
        assert_true(!file_id.empty(), "File ID should not be empty");
        assert_true(engine.get_file_count() == 1, "File count should be 1 after storing");
        assert_true(engine.get_total_storage_used() == data.size(), "Storage used should match file size");
        
        // Retrieve file
        auto retrieve_future = engine.retrieve_file_async(file_id);
        std::vector<uint8_t> retrieved_data = retrieve_future.get();
        
        assert_true(retrieved_data.size() == data.size(), "Retrieved data size should match original");
        assert_true(retrieved_data == data, "Retrieved data should match original data");
        
        // Test metadata
        auto metadata = engine.get_file_metadata(file_id);
        assert_true(metadata != nullptr, "Metadata should not be null");
        assert_true(metadata->filename == filename, "Metadata filename should match");
        assert_true(metadata->size == data.size(), "Metadata size should match");
    }

    void test_file_deletion() {
        std::cout << "\n=== Testing File Deletion ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        // Store a file
        std::string filename = "delete_test.txt";
        std::vector<uint8_t> data{'t', 'e', 's', 't'};
        
        auto store_future = engine.store_file_async(filename, data);
        std::string file_id = store_future.get();
        
        assert_true(engine.get_file_count() == 1, "File count should be 1 before deletion");
        
        // Delete file
        auto delete_future = engine.delete_file_async(file_id);
        bool deleted = delete_future.get();
        
        assert_true(deleted, "File should be successfully deleted");
        assert_true(engine.get_file_count() == 0, "File count should be 0 after deletion");
        assert_true(engine.get_total_storage_used() == 0, "Storage used should be 0 after deletion");
        
        // Try to retrieve deleted file
        auto retrieve_future = engine.retrieve_file_async(file_id);
        try {
            retrieve_future.get();
            assert_true(false, "Should throw exception when retrieving deleted file");
        } catch (const std::exception& e) {
            assert_true(true, "Should throw exception when retrieving deleted file");
        }
    }

    void test_multiple_files() {
        std::cout << "\n=== Testing Multiple Files ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        std::vector<std::string> file_ids;
        const int num_files = 5;
        
        // Store multiple files
        for (int i = 0; i < num_files; ++i) {
            std::string filename = "test_file_" + std::to_string(i) + ".txt";
            std::string content = "Content for file " + std::to_string(i);
            std::vector<uint8_t> data(content.begin(), content.end());
            
            auto store_future = engine.store_file_async(filename, data);
            file_ids.push_back(store_future.get());
        }
        
        assert_true(engine.get_file_count() == num_files, "File count should match number of stored files");
        
        // List all files
        auto all_files = engine.list_files();
        assert_true(all_files.size() == num_files, "List should return all files");
        
        // Verify each file can be retrieved
        for (const auto& file_id : file_ids) {
            auto retrieve_future = engine.retrieve_file_async(file_id);
            auto data = retrieve_future.get();
            assert_true(!data.empty(), "Each file should be retrievable");
        }
    }

    void test_concurrent_operations() {
        std::cout << "\n=== Testing Concurrent Operations ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        const int num_threads = 10;
        const int files_per_thread = 3;
        std::vector<std::thread> threads;
        std::vector<std::string> all_file_ids;
        std::mutex file_ids_mutex;
        
        // Concurrent file storage
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&engine, &all_file_ids, &file_ids_mutex, t, files_per_thread]() {
                std::vector<std::string> thread_file_ids;
                
                for (int i = 0; i < files_per_thread; ++i) {
                    std::string filename = "thread_" + std::to_string(t) + "_file_" + std::to_string(i) + ".txt";
                    std::string content = "Thread " + std::to_string(t) + " file " + std::to_string(i);
                    std::vector<uint8_t> data(content.begin(), content.end());
                    
                    auto store_future = engine.store_file_async(filename, data);
                    thread_file_ids.push_back(store_future.get());
                }
                
                std::lock_guard<std::mutex> lock(file_ids_mutex);
                all_file_ids.insert(all_file_ids.end(), thread_file_ids.begin(), thread_file_ids.end());
            });
        }
        
        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
        
        assert_true(engine.get_file_count() == num_threads * files_per_thread, 
                   "File count should match expected number from concurrent operations");
        assert_true(all_file_ids.size() == num_threads * files_per_thread, 
                   "All file IDs should be collected");
        
        // Verify all files can be retrieved
        for (const auto& file_id : all_file_ids) {
            auto retrieve_future = engine.retrieve_file_async(file_id);
            auto data = retrieve_future.get();
            assert_true(!data.empty(), "Each concurrently stored file should be retrievable");
        }
    }

    void test_large_file_handling() {
        std::cout << "\n=== Testing Large File Handling ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        // Create large file data (10MB)
        const size_t large_size = 10 * 1024 * 1024;
        std::vector<uint8_t> large_data(large_size);
        
        // Fill with pattern
        for (size_t i = 0; i < large_size; ++i) {
            large_data[i] = static_cast<uint8_t>(i % 256);
        }
        
        // Store large file
        auto store_future = engine.store_file_async("large_file.bin", large_data);
        std::string file_id = store_future.get();
        
        assert_true(!file_id.empty(), "Large file should be stored successfully");
        assert_true(engine.get_total_storage_used() == large_size, "Storage used should match large file size");
        
        // Retrieve large file
        auto retrieve_future = engine.retrieve_file_async(file_id);
        std::vector<uint8_t> retrieved_data = retrieve_future.get();
        
        assert_true(retrieved_data.size() == large_size, "Retrieved large file size should match");
        assert_true(retrieved_data == large_data, "Retrieved large file data should match");
    }

    void test_error_handling() {
        std::cout << "\n=== Testing Error Handling ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        // Test retrieving non-existent file
        auto retrieve_future = engine.retrieve_file_async("non_existent_file_id");
        try {
            retrieve_future.get();
            assert_true(false, "Should throw exception for non-existent file");
        } catch (const std::exception& e) {
            assert_true(true, "Should throw exception for non-existent file");
        }
        
        // Test deleting non-existent file
        auto delete_future = engine.delete_file_async("non_existent_file_id");
        bool deleted = delete_future.get();
        assert_true(!deleted, "Should return false when deleting non-existent file");
    }

    void test_configuration() {
        std::cout << "\n=== Testing Configuration ===" << std::endl;
        
        StorageEngine engine(test_storage_path);
        
        // Test setting configuration
        size_t max_file_size = 1024 * 1024; // 1MB
        size_t storage_quota = 100 * 1024 * 1024; // 100MB
        
        engine.set_max_file_size(max_file_size);
        engine.set_storage_quota(storage_quota);
        engine.enable_compression(true);
        
        assert_true(engine.is_healthy(), "Engine should remain healthy after configuration");
        
        // Test quota enforcement would require storing files beyond quota
        // This is simplified for demonstration
    }

    void run_all_tests() {
        std::cout << "Starting DistributedFS Storage Engine Tests..." << std::endl;
        
        test_storage_engine_initialization();
        test_file_storage_and_retrieval();
        test_file_deletion();
        test_multiple_files();
        test_concurrent_operations();
        test_large_file_handling();
        test_error_handling();
        test_configuration();
        
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "Tests passed: " << tests_passed << std::endl;
        std::cout << "Tests failed: " << tests_failed << std::endl;
        
        if (tests_failed == 0) {
            std::cout << "🎉 All tests passed!" << std::endl;
        } else {
            std::cout << "❌ Some tests failed. Please review the output above." << std::endl;
        }
    }
};

int main() {
    TestRunner runner;
    runner.run_all_tests();
    return 0;
} 
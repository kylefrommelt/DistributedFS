#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <csignal>
#include <atomic>
#include <sstream>
#include <iomanip>
#include "storage_engine.h"

using namespace distributedfs;

class DistributedFSApplication {
private:
    std::unique_ptr<StorageEngine> storage_engine_;
    std::string storage_path_;
    std::atomic<bool> running_;
    
public:
    DistributedFSApplication(const std::string& storage_path) 
        : storage_path_(storage_path), running_(true) {
        storage_engine_ = std::make_unique<StorageEngine>(storage_path);
    }
    
    ~DistributedFSApplication() {
        shutdown();
    }
    
    void run() {
        std::cout << "=== DistributedFS Storage Engine ===" << std::endl;
        std::cout << "Starting distributed file storage system..." << std::endl;
        std::cout << "Storage path: " << storage_path_ << std::endl;
        
        // Display system information
        display_system_info();
        
        // Set up signal handlers
        setup_signal_handlers();
        
        // Run interactive mode
        run_interactive_mode();
    }
    
private:
    void display_system_info() {
        std::cout << "\n=== System Information ===" << std::endl;
        std::cout << "Storage healthy: " << (storage_engine_->is_healthy() ? "Yes" : "No") << std::endl;
        std::cout << "File count: " << storage_engine_->get_file_count() << std::endl;
        std::cout << "Storage used: " << format_bytes(storage_engine_->get_total_storage_used()) << std::endl;
        std::cout << "Hardware threads: " << std::thread::hardware_concurrency() << std::endl;
    }
    
    void setup_signal_handlers() {
        std::signal(SIGINT, [](int signal) {
            std::cout << "\nReceived interrupt signal. Shutting down gracefully..." << std::endl;
            // Note: This is a simplified signal handler. In production, use proper signal handling.
            exit(0);
        });
    }
    
    void run_interactive_mode() {
        std::cout << "\n=== Interactive Mode ===" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  store <filename> <content>  - Store a file" << std::endl;
        std::cout << "  retrieve <file_id>          - Retrieve a file" << std::endl;
        std::cout << "  delete <file_id>            - Delete a file" << std::endl;
        std::cout << "  list                        - List all files" << std::endl;
        std::cout << "  stats                       - Show storage statistics" << std::endl;
        std::cout << "  benchmark                   - Run performance benchmark" << std::endl;
        std::cout << "  demo                        - Run demonstration" << std::endl;
        std::cout << "  help                        - Show this help" << std::endl;
        std::cout << "  quit                        - Exit application" << std::endl;
        std::cout << std::endl;
        
        std::string command;
        while (running_ && std::cout << "distributedfs> " && std::cin >> command) {
            try {
                if (command == "store") {
                    handle_store_command();
                } else if (command == "retrieve") {
                    handle_retrieve_command();
                } else if (command == "delete") {
                    handle_delete_command();
                } else if (command == "list") {
                    handle_list_command();
                } else if (command == "stats") {
                    handle_stats_command();
                } else if (command == "benchmark") {
                    handle_benchmark_command();
                } else if (command == "demo") {
                    handle_demo_command();
                } else if (command == "help") {
                    run_interactive_mode();
                    return;
                } else if (command == "quit" || command == "exit") {
                    break;
                } else {
                    std::cout << "Unknown command: " << command << std::endl;
                    std::cout << "Type 'help' for available commands." << std::endl;
                }
            } catch (const std::exception& e) {
                std::cout << "Error: " << e.what() << std::endl;
            }
        }
    }
    
    void handle_store_command() {
        std::string filename, content;
        std::cin >> filename >> content;
        
        std::vector<uint8_t> data(content.begin(), content.end());
        auto future = storage_engine_->store_file_async(filename, data);
        
        std::cout << "Storing file..." << std::endl;
        std::string file_id = future.get();
        std::cout << "File stored successfully! ID: " << file_id << std::endl;
    }
    
    void handle_retrieve_command() {
        std::string file_id;
        std::cin >> file_id;
        
        auto future = storage_engine_->retrieve_file_async(file_id);
        
        std::cout << "Retrieving file..." << std::endl;
        std::vector<uint8_t> data = future.get();
        
        std::string content(data.begin(), data.end());
        std::cout << "File content: " << content << std::endl;
    }
    
    void handle_delete_command() {
        std::string file_id;
        std::cin >> file_id;
        
        auto future = storage_engine_->delete_file_async(file_id);
        
        std::cout << "Deleting file..." << std::endl;
        bool success = future.get();
        
        if (success) {
            std::cout << "File deleted successfully!" << std::endl;
        } else {
            std::cout << "Failed to delete file. File may not exist." << std::endl;
        }
    }
    
    void handle_list_command() {
        auto files = storage_engine_->list_files();
        
        std::cout << "=== File List ===" << std::endl;
        std::cout << "Total files: " << files.size() << std::endl;
        
        for (const auto& file : files) {
            std::cout << "ID: " << file->file_id << std::endl;
            std::cout << "  Filename: " << file->filename << std::endl;
            std::cout << "  Size: " << format_bytes(file->size) << std::endl;
            std::cout << "  Checksum: " << file->checksum.substr(0, 16) << "..." << std::endl;
            std::cout << std::endl;
        }
    }
    
    void handle_stats_command() {
        std::cout << "=== Storage Statistics ===" << std::endl;
        std::cout << "File count: " << storage_engine_->get_file_count() << std::endl;
        std::cout << "Storage used: " << format_bytes(storage_engine_->get_total_storage_used()) << std::endl;
        std::cout << "System healthy: " << (storage_engine_->is_healthy() ? "Yes" : "No") << std::endl;
        
        auto files = storage_engine_->list_files();
        if (!files.empty()) {
            size_t total_size = 0;
            size_t min_size = SIZE_MAX;
            size_t max_size = 0;
            
            for (const auto& file : files) {
                total_size += file->size;
                min_size = std::min(min_size, file->size);
                max_size = std::max(max_size, file->size);
            }
            
            std::cout << "Average file size: " << format_bytes(total_size / files.size()) << std::endl;
            std::cout << "Smallest file: " << format_bytes(min_size) << std::endl;
            std::cout << "Largest file: " << format_bytes(max_size) << std::endl;
        }
    }
    
    void handle_benchmark_command() {
        std::cout << "=== Performance Benchmark ===" << std::endl;
        
        // Benchmark file storage
        const int num_files = 100;
        const size_t file_size = 1024; // 1KB files
        
        std::vector<uint8_t> test_data(file_size, 'X');
        std::vector<std::string> file_ids;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Store files
        std::cout << "Storing " << num_files << " files..." << std::endl;
        for (int i = 0; i < num_files; ++i) {
            std::string filename = "benchmark_file_" + std::to_string(i) + ".txt";
            auto future = storage_engine_->store_file_async(filename, test_data);
            file_ids.push_back(future.get());
        }
        
        auto store_time = std::chrono::high_resolution_clock::now();
        
        // Retrieve files
        std::cout << "Retrieving " << num_files << " files..." << std::endl;
        for (const auto& file_id : file_ids) {
            auto future = storage_engine_->retrieve_file_async(file_id);
            future.get();
        }
        
        auto retrieve_time = std::chrono::high_resolution_clock::now();
        
        // Calculate performance metrics
        auto store_duration = std::chrono::duration_cast<std::chrono::milliseconds>(store_time - start_time);
        auto retrieve_duration = std::chrono::duration_cast<std::chrono::milliseconds>(retrieve_time - store_time);
        
        double store_throughput = (num_files * file_size) / (store_duration.count() / 1000.0) / 1024.0 / 1024.0;
        double retrieve_throughput = (num_files * file_size) / (retrieve_duration.count() / 1000.0) / 1024.0 / 1024.0;
        
        std::cout << "Store time: " << store_duration.count() << " ms" << std::endl;
        std::cout << "Retrieve time: " << retrieve_duration.count() << " ms" << std::endl;
        std::cout << "Store throughput: " << store_throughput << " MB/s" << std::endl;
        std::cout << "Retrieve throughput: " << retrieve_throughput << " MB/s" << std::endl;
        
        // Clean up benchmark files
        std::cout << "Cleaning up benchmark files..." << std::endl;
        for (const auto& file_id : file_ids) {
            auto future = storage_engine_->delete_file_async(file_id);
            future.get();
        }
        
        std::cout << "Benchmark completed!" << std::endl;
    }
    
    void handle_demo_command() {
        std::cout << "=== DistributedFS Demonstration ===" << std::endl;
        
        try {
            // Demo 1: Store and retrieve a text file
            std::cout << "\n1. Storing a text file..." << std::endl;
            std::string demo_content = "Hello, World! This is a demonstration of DistributedFS.";
            std::vector<uint8_t> demo_data(demo_content.begin(), demo_content.end());
            
            auto store_future = storage_engine_->store_file_async("demo.txt", demo_data);
            std::string file_id = store_future.get();
            std::cout << "   File stored with ID: " << file_id << std::endl;
            
            // Demo 2: Retrieve the file
            std::cout << "\n2. Retrieving the file..." << std::endl;
            auto retrieve_future = storage_engine_->retrieve_file_async(file_id);
            std::vector<uint8_t> retrieved_data = retrieve_future.get();
            
            std::string retrieved_content(retrieved_data.begin(), retrieved_data.end());
            std::cout << "   Retrieved content: " << retrieved_content << std::endl;
            
            // Demo 3: Show file metadata
            std::cout << "\n3. File metadata:" << std::endl;
            auto metadata = storage_engine_->get_file_metadata(file_id);
            if (metadata) {
                std::cout << "   Filename: " << metadata->filename << std::endl;
                std::cout << "   Size: " << format_bytes(metadata->size) << std::endl;
                std::cout << "   Checksum: " << metadata->checksum.substr(0, 16) << "..." << std::endl;
            }
            
            // Demo 4: Concurrent operations
            std::cout << "\n4. Demonstrating concurrent operations..." << std::endl;
            std::vector<std::future<std::string>> futures;
            
            for (int i = 0; i < 5; ++i) {
                std::string content = "Concurrent file " + std::to_string(i);
                std::vector<uint8_t> data(content.begin(), content.end());
                futures.push_back(storage_engine_->store_file_async("concurrent_" + std::to_string(i) + ".txt", data));
            }
            
            std::cout << "   Stored " << futures.size() << " files concurrently" << std::endl;
            
            // Demo 5: List all files
            std::cout << "\n5. Current file list:" << std::endl;
            auto files = storage_engine_->list_files();
            std::cout << "   Total files: " << files.size() << std::endl;
            
            // Demo 6: System statistics
            std::cout << "\n6. System statistics:" << std::endl;
            std::cout << "   File count: " << storage_engine_->get_file_count() << std::endl;
            std::cout << "   Storage used: " << format_bytes(storage_engine_->get_total_storage_used()) << std::endl;
            std::cout << "   System healthy: " << (storage_engine_->is_healthy() ? "Yes" : "No") << std::endl;
            
            std::cout << "\nDemonstration completed successfully!" << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "Demo error: " << e.what() << std::endl;
        }
    }
    
    void shutdown() {
        running_ = false;
        std::cout << "Shutting down DistributedFS..." << std::endl;
    }
    
    std::string format_bytes(size_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        int unit_index = 0;
        double size = static_cast<double>(bytes);
        
        while (size >= 1024.0 && unit_index < 4) {
            size /= 1024.0;
            unit_index++;
        }
        
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << size << " " << units[unit_index];
        return oss.str();
    }
};

int main(int argc, char* argv[]) {
    std::string storage_path = "/tmp/distributedfs_storage";
    
    // Parse command line arguments
    if (argc > 1) {
        storage_path = argv[1];
    }
    
    try {
        DistributedFSApplication app(storage_path);
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 
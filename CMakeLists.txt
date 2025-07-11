cmake_minimum_required(VERSION 3.15)
project(DistributedFS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Boost REQUIRED COMPONENTS system filesystem thread)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(src/cpp/include)

# Source files
set(SOURCES
    src/cpp/src/storage_engine.cpp
    src/cpp/src/file_manager.cpp
    src/cpp/src/crypto_manager.cpp
    src/cpp/src/thread_pool.cpp
    src/cpp/src/network_server.cpp
)

# Create main library
add_library(distributedfs_lib ${SOURCES})

# Link libraries
target_link_libraries(distributedfs_lib
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Main executable
add_executable(distributedfs src/cpp/src/main.cpp)
target_link_libraries(distributedfs distributedfs_lib)

# Compiler flags
target_compile_options(distributedfs_lib PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -O3>
)

# Enable testing
enable_testing()

# Test executable
add_executable(test_distributedfs
    tests/cpp/test_storage_engine.cpp
    tests/cpp/test_file_manager.cpp
    tests/cpp/test_crypto_manager.cpp
)

target_link_libraries(test_distributedfs distributedfs_lib)
add_test(NAME unit_tests COMMAND test_distributedfs)

# Install targets
install(TARGETS distributedfs DESTINATION bin)
install(TARGETS distributedfs_lib DESTINATION lib) 
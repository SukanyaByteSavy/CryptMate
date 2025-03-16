cmake_minimum_required(VERSION 3.10)
project(crypto_impl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Python and pybind11
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
find_package(Python3 COMPONENTS Development)
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -c "import pybind11; print(pybind11.get_cmake_dir())"
    OUTPUT_VARIABLE pybind11_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
find_package(pybind11 CONFIG REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

pybind11_add_module(crypto_impl src/crypto_impl.cpp)
target_link_libraries(crypto_impl PRIVATE OpenSSL::SSL OpenSSL::Crypto)
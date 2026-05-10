cmake_minimum_required(VERSION 3.20)
project(metacrypt-cpp VERSION 0.4.0 LANGUAGES CXX)

option(METACRYPT_BUILD_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(METACRYPT_BUILD_TESTS "Build tests" ${PROJECT_IS_TOP_LEVEL})

add_library(metacrypt-cpp INTERFACE)
add_library(metacrypt::metacrypt ALIAS metacrypt-cpp)
target_compile_features(metacrypt-cpp INTERFACE cxx_std_20)
target_include_directories(metacrypt-cpp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_definitions(metacrypt-cpp INTERFACE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(metacrypt-cpp INTERFACE bcrypt)

if(METACRYPT_BUILD_EXAMPLES)
    add_executable(metacrypt-roundtrip examples/roundtrip.cpp)
    target_link_libraries(metacrypt-roundtrip PRIVATE metacrypt::metacrypt)

    add_executable(metacrypt-inspect examples/inspect.cpp)
    target_link_libraries(metacrypt-inspect PRIVATE metacrypt::metacrypt)
endif()

if(METACRYPT_BUILD_TESTS)
    enable_testing()
    add_executable(metacrypt-tests tests/test_cases.cpp)
    target_link_libraries(metacrypt-tests PRIVATE metacrypt::metacrypt)
    add_test(NAME metacrypt-tests COMMAND metacrypt-tests)
endif()

cmake_minimum_required(VERSION 3.14)

project(Obfuscate)

option(GENERATE_TESTS "GENERATE_TESTS" ON)
option(GENERATE_DEMO "GENERATE_DEMO" ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set unix platforms to output executables to Release and Debug folders (Windows does by default)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug)

if (GENERATE_DEMO)
    find_package(Threads REQUIRED)

    add_executable(demo obfuscate.h demo.cpp)
    target_link_libraries(demo PRIVATE Threads::Threads)

    add_executable(demo_freestanding obfuscate.h demo.cpp)
    target_link_libraries(demo_freestanding PRIVATE Threads::Threads)
    target_compile_definitions(demo_freestanding PRIVATE AY_OBFUSCATE_FREESTANDING=1)
    if (MSVC)
        target_compile_options(demo_freestanding PRIVATE /Zc:threadSafeInit-)
    endif()
endif()

# Unit tests
if (GENERATE_TESTS)
    include(CTest)

    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(test_unit obfuscate.h test_unit.cpp)
    target_link_libraries(test_unit gtest_main)

    add_test(NAME test_unit COMMAND test_unit)

    add_executable(test_unit_freestanding obfuscate.h test_unit.cpp)
    target_link_libraries(test_unit_freestanding gtest_main)
    target_compile_definitions(test_unit_freestanding PRIVATE AY_OBFUSCATE_FREESTANDING=1)
    if (MSVC)
        target_compile_options(test_unit_freestanding PRIVATE /Zc:threadSafeInit-)
    endif()

    add_test(NAME test_unit_freestanding COMMAND test_unit_freestanding)

    add_executable(test_obfuscated obfuscate.h test_obfuscated.cpp)
    set_target_properties(test_obfuscated PROPERTIES SUFFIX ".out")

    add_executable(test_obfuscated_freestanding obfuscate.h test_obfuscated.cpp)
    target_compile_definitions(test_obfuscated_freestanding PRIVATE AY_OBFUSCATE_FREESTANDING=1)
    if (MSVC)
        target_compile_options(test_obfuscated_freestanding PRIVATE /Zc:threadSafeInit-)
    endif()
    set_target_properties(test_obfuscated_freestanding PROPERTIES SUFFIX ".out")

    if (GENERATE_DEMO)
        add_test(NAME demo COMMAND demo)
        add_test(NAME demo_freestanding COMMAND demo_freestanding)
    endif()
endif()

# Bloat test
add_executable(test_bloat_on obfuscate.h test_bloat.cpp)
add_executable(test_bloat_off obfuscate.h test_bloat.cpp)
target_compile_definitions(test_bloat_on PRIVATE USE_AY_OBFUSCATE=1)

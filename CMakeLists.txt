cmake_minimum_required(VERSION 3.16)
project(parallax_url_dump VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PARALLAX_BUILD_TOOLS "Build the parallax_dump CLI" ON)
option(PARALLAX_BUILD_TESTS "Build native regression tests" ON)
option(PARALLAX_WITH_CAPSTONE "Use Capstone for instruction-level xrefs when available" ON)
option(PARALLAX_WITH_MINIZIP_NG "Use minizip-ng ZIP backend when available" OFF)
option(PARALLAX_WITH_LIEF "Use LIEF ELF backend when available" OFF)
option(PARALLAX_WITH_NLOHMANN_JSON "Use nlohmann/json when available" OFF)

find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

set(PARALLAX_SOURCES
    src/common.cpp
    src/url.cpp
    src/zip.cpp
    src/elf.cpp
    src/dex.cpp
    src/address.cpp
    src/xref.cpp
    src/obfuscation.cpp
    src/report.cpp
    src/runtime.cpp
    src/analyzer.cpp)

set(PARALLAX_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(PARALLAX_LIBS ZLIB::ZLIB Threads::Threads)

# Capstone: optional instruction-level evidence.
if(PARALLAX_WITH_CAPSTONE)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(CAPSTONE QUIET capstone)
    endif()
    if(CAPSTONE_FOUND)
        list(APPEND PARALLAX_INCLUDES ${CAPSTONE_INCLUDE_DIRS})
        list(APPEND PARALLAX_LIBS ${CAPSTONE_LIBRARIES})
        link_directories(${CAPSTONE_LIBRARY_DIRS})
        add_compile_definitions(PARALLAX_HAVE_CAPSTONE=1)
        message(STATUS "Parallax: Capstone enabled (${CAPSTONE_VERSION})")
    else()
        message(STATUS "Parallax: Capstone not found; using raw-pointer xrefs only")
    endif()
endif()

# minizip-ng classic compatibility API: optional ZIP backend.
if(PARALLAX_WITH_MINIZIP_NG)
    find_path(MINIZIP_INCLUDE_DIR minizip/unzip.h)
    find_library(MINIZIP_LIBRARY NAMES minizip minizip-ng)
    if(MINIZIP_INCLUDE_DIR AND MINIZIP_LIBRARY)
        list(APPEND PARALLAX_SOURCES src/zip_minizip.cpp)
        list(APPEND PARALLAX_INCLUDES ${MINIZIP_INCLUDE_DIR})
        list(APPEND PARALLAX_LIBS ${MINIZIP_LIBRARY})
        add_compile_definitions(PARALLAX_HAVE_MINIZIP_NG=1)
        message(STATUS "Parallax: minizip-ng backend enabled")
    else()
        message(STATUS "Parallax: minizip-ng not found; using built-in ZIP64 reader")
    endif()
endif()

# LIEF: optional ELF backend. Provide -DLIEF_DIR=... if installed in a custom path.
if(PARALLAX_WITH_LIEF)
    find_package(LIEF QUIET)
    if(LIEF_FOUND)
        list(APPEND PARALLAX_SOURCES src/elf_lief.cpp)
        list(APPEND PARALLAX_LIBS LIEF::ELF)
        add_compile_definitions(PARALLAX_HAVE_LIEF=1)
        message(STATUS "Parallax: LIEF backend enabled")
    else()
        message(STATUS "Parallax: LIEF not found; using built-in ELF parser")
    endif()
endif()

if(PARALLAX_WITH_NLOHMANN_JSON)
    find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
    if(NLOHMANN_JSON_INCLUDE_DIR)
        list(APPEND PARALLAX_INCLUDES ${NLOHMANN_JSON_INCLUDE_DIR})
        add_compile_definitions(PARALLAX_HAVE_NLOHMANN_JSON=1)
        message(STATUS "Parallax: nlohmann/json enabled")
    else()
        message(STATUS "Parallax: nlohmann/json not found; using built-in JSON writer")
    endif()
endif()

add_library(parallax_core STATIC ${PARALLAX_SOURCES})
target_include_directories(parallax_core PUBLIC ${PARALLAX_INCLUDES})
target_link_libraries(parallax_core PUBLIC ${PARALLAX_LIBS})

if(PARALLAX_BUILD_TOOLS)
    add_executable(parallax_dump tools/parallax_dump.cpp)
    target_link_libraries(parallax_dump PRIVATE parallax_core)
endif()

if(PARALLAX_BUILD_TESTS)
    enable_testing()
    add_executable(parallax_tests tests/test_core.cpp)
    target_link_libraries(parallax_tests PRIVATE parallax_core)
    add_test(NAME parallax_core COMMAND parallax_tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures)
endif()

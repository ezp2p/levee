cmake_minimum_required(VERSION 3.21)
project(levee VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# GCC 12 and older build some coroutines wrong when optimising (Pond's docs/design.md, "Coroutines"); Levee uses callbacks,
# not coroutines, but keeps to the same compilers as Pond to be safe.

if(APPLE AND EXISTS /opt/homebrew)
  if(NOT OPENSSL_ROOT_DIR AND EXISTS /opt/homebrew/opt/openssl)
    set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl)
  endif()
  list(APPEND CMAKE_PREFIX_PATH /opt/homebrew)
endif()

# Drogon for HTTP and TLS, built from source at a fixed release, without any database: a Levee keeps its files on disk.
include(FetchContent)
set(BUILD_CTL OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_BROTLI OFF CACHE BOOL "" FORCE)
set(BUILD_YAML_CONFIG OFF CACHE BOOL "" FORCE)
set(BUILD_ORM OFF CACHE BOOL "" FORCE)
set(BUILD_REDIS OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CMAKE_DISABLE_FIND_PACKAGE_pg TRUE)
set(CMAKE_DISABLE_FIND_PACKAGE_SQLite3 TRUE)
set(CMAKE_DISABLE_FIND_PACKAGE_MySQL TRUE)
# patches/: Drogon leaves a connection open after a 204 even when the request asked for it to close (as Pond's)
set(DROGON_PATCH ${CMAKE_CURRENT_SOURCE_DIR}/patches/drogon-close-after-no-content.patch)
FetchContent_Declare(drogon
  GIT_REPOSITORY https://github.com/drogonframework/drogon.git
  GIT_TAG v1.9.14
  GIT_SHALLOW TRUE
  GIT_SUBMODULES trantor
  PATCH_COMMAND sh -c "git apply --reverse --check ${DROGON_PATCH} 2>/dev/null || git apply ${DROGON_PATCH}")
FetchContent_MakeAvailable(drogon)
target_compile_options(trantor PRIVATE -Wno-error=deprecated-declarations)

find_package(yaml-cpp REQUIRED)
if(NOT TARGET yaml-cpp::yaml-cpp AND TARGET yaml-cpp)
  add_library(yaml-cpp::yaml-cpp ALIAS yaml-cpp)
endif()
find_package(OpenSSL 3 REQUIRED)

# libpuddle-proto: the protocol's bytes, shared with Puddle and Pond (a git submodule: git submodule update --init)
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/protocol/lib/CMakeLists.txt)
  message(FATAL_ERROR "third_party/protocol is missing: run git submodule update --init")
endif()
add_subdirectory(third_party/protocol/lib EXCLUDE_FROM_ALL)

add_library(levee_lib STATIC
  src/config.cpp
  src/levee.cpp
  src/store.cpp
  src/tls.cpp
  src/turn.cpp
  src/util.cpp)
target_include_directories(levee_lib PUBLIC src)
target_link_libraries(levee_lib PUBLIC drogon yaml-cpp::yaml-cpp puddle_proto OpenSSL::Crypto)
target_compile_options(levee_lib PRIVATE -Wall -Wextra)

add_executable(leveed src/leveed.cpp)
target_link_libraries(leveed PRIVATE levee_lib)
add_executable(leveectl src/leveectl.cpp)
target_link_libraries(leveectl PRIVATE levee_lib)
install(TARGETS leveed leveectl RUNTIME DESTINATION bin)

enable_testing()
foreach(t store turn levee)
  add_executable(${t}_test tests/${t}_test.cpp)
  target_link_libraries(${t}_test PRIVATE levee_lib OpenSSL::SSL)
  target_compile_options(${t}_test PRIVATE -Wall -Wextra)
  target_compile_definitions(${t}_test PRIVATE LEVEE_BIN_DIR="${CMAKE_CURRENT_BINARY_DIR}")
  add_test(NAME ${t} COMMAND ${t}_test)
  set_tests_properties(${t} PROPERTIES TIMEOUT 180)
endforeach()
add_dependencies(levee_test leveed leveectl)

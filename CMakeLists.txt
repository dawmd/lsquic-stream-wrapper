cmake_minimum_required(VERSION 3.23)
project(seastar_echo_quic)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_COMPILER /usr/bin/clang++)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -Wshadow -Wpedantic")

find_package(Seastar REQUIRED)

set(FMT_LIB /home/dawid/Downloads/fmt-8.1.1/build/libfmt.a)

set(BORINGSSL_DIR /home/dawid/Programming/Sem5/zpp/boringssl) # Adjust the path.
set(BORINGSSL_INCLUDE_DIR ${BORINGSSL_DIR}/include)

# Find boringssl crypto library
set(BORINGSSL_CRYPTO_LIB_NAME libcrypto.a) # One can change to search for dynamic library (.so)
set(BORINGSSL_CRYPTO_LIB_DIR ${BORINGSSL_DIR}/crypto) # Adjust the path.
message(STATUS "Searching for boringssl crypto library (${BORINGSSL_CRYPTO_LIB_NAME}) in ${BORINGSSL_CRYPTO_LIB_DIR}...")
find_library(
        BORINGSSL_CRYPTO_LIB
        NAMES ${BORINGSSL_CRYPTO_LIB_NAME}
        HINTS ${BORINGSSL_CRYPTO_LIB_DIR}
        REQUIRED
)
if(BORINGSSL_CRYPTO_LIB)
    message(STATUS "boringssl crypto library found - ${BORINGSSL_CRYPTO_LIB}")
endif()

# Find boringssl ssl library
set(BORINGSSL_SSL_LIB_NAME libssl.a) # One can change to search for dynamic library (.so)
set(BORINGSSL_SSL_LIB_DIR ${BORINGSSL_DIR}/ssl)
message(STATUS "Searching for boringssl ssl library (${BORINGSSL_SSL_LIB_NAME}) in ${BORINGSSL_SSL_LIB_DIR}...")
find_library(
        BORINGSSL_SSL_LIB
        NAMES ${BORINGSSL_SSL_LIB_NAME}
        HINTS ${BORINGSSL_SSL_LIB_DIR}
        REQUIRED
)
if(BORINGSSL_SSL_LIB)
    message(STATUS "boringssl ssl library found - ${BORINGSSL_SSL_LIB}")
endif()

message(STATUS "Searching for zlib package...")
find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
    message(STATUS "zlib package found - ${ZLIB_DIR}")
endif()

message(STATUS "Searching for lsquic library...")
find_library(LSQUIC_LIB lsquic REQUIRED)
if(LSQUIC_LIB)
    message(STATUS "lsquic library found - ${LSQUIC_LIB}")
endif()

list(APPEND INCLUDE_FILES_DIR include ${BORINGSSL_INCLUDE_DIR})
list(APPEND LIBS ${LSQUIC_LIB} ${BORINGSSL_SSL_LIB} ${BORINGSSL_CRYPTO_LIB} Seastar::seastar ${FMT_LIB} ZLIB::ZLIB)

set(DATAGRAMSIZE 3000)

set(SERVER_EXEC echo_server)
set(SERVER_SRC
    # src/echo_server.cc
    # src/ssl_handler.cc
    src/main.cc
    src/quic/server.cc
    src/quic/detail/callbacks.cc
    src/quic/ssl/ssl_handler.cc
)
# set(SERVER_SRC src/main.cc)

# set(CLIENT_EXEC echo_client)
# set(CLIENT_SRC
#     src/echo_client.cc
# )

add_executable(${SERVER_EXEC} ${SERVER_SRC})
target_include_directories(${SERVER_EXEC} PRIVATE ${INCLUDE_FILES_DIR})
target_link_libraries(${SERVER_EXEC} ${LIBS})
target_compile_definitions(${SERVER_EXEC} PRIVATE DATAGRAM_SIZE=${DATAGRAMSIZE})
target_compile_definitions(${SERVER_EXEC} PRIVATE PROJECT_ROOT_PATH="${PROJECT_SOURCE_DIR}")

# add_executable(${CLIENT_EXEC} ${CLIENT_SRC})
# target_include_directories(${CLIENT_EXEC} PRIVATE ${INCLUDE_FILES_DIR})
# target_link_libraries(${CLIENT_EXEC} ${LIBS})
# target_compile_definitions(${CLIENT_EXEC} PRIVATE DATAGRAM_SIZE=${DATAGRAMSIZE})
# target_compile_definitions(${CLIENT_EXEC} PRIVATE PROJECT_ROOT_PATH="${PROJECT_SOURCE_DIR}")

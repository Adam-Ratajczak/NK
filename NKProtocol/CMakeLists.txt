cmake_minimum_required(VERSION 3.16)
project(NKProtocol C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(nk_protocol STATIC
    src/nk_protocol.c
)

target_include_directories(nk_protocol
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(EMSCRIPTEN)
    target_link_options(nk_protocol PRIVATE "-sUSE_ZLIB=1")
    target_include_directories(nk_protocol PUBLIC
        /opt/sodium-wasm/include
    )
    target_link_directories(nk_protocol PUBLIC
        /opt/sodium-wasm/lib
    )
    target_link_libraries(nk_protocol PUBLIC sodium)
else()
    find_package(ZLIB REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)

    target_include_directories(nk_protocol PUBLIC ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(nk_protocol
        PUBLIC
            ZLIB::ZLIB
            ${SODIUM_LIBRARIES}
    )
endif()

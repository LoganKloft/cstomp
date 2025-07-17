
cmake_minimum_required(VERSION 3.12)

set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)
project(cstomp VERSION 1.0.0)

find_package(libuv CONFIG REQUIRED)
find_package(unofficial-utf8proc CONFIG REQUIRED)

add_library(cstomp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cstomp.c)

target_link_libraries(cstomp PUBLIC
    libuv::uv
    utf8proc)

target_include_directories(cstomp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(example)
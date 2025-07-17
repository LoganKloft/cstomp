cmake_minimum_required(VERSION 3.12)

set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)
project(cstomp-examples VERSION 1.0.0 LANGUAGES C)

add_executable(example-client 
    ${CMAKE_CURRENT_SOURCE_DIR}/client/main.c)

target_include_directories(example-client PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)

target_link_libraries(example-client PRIVATE
    cstomp)
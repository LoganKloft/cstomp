cmake_minimum_required(VERSION 3.12)

set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)
project(cstomp-test-uv VERSION 1.0.0 LANGUAGES C)

add_executable(cstomp-test-uv 
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

target_link_libraries(cstomp-test-uv PRIVATE
    cstomp)
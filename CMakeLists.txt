
cmake_minimum_required(VERSION 3.12)

# Set toolchain file conditionally - only if VCPKG_ROOT is set
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)
endif()

project(cstomp VERSION 1.0.0 LANGUAGES C)

# Platform-specific configurations
if(WIN32)
    # Windows-specific settings
    add_definitions(-D_WIN32_WINNT=0x0600)  # Windows Vista or later
    if(MSVC)
        # MSVC-specific flags
        add_compile_options(/W3)
        add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    endif()
elseif(UNIX AND NOT APPLE)
    # Linux-specific settings
    add_compile_options(-Wall -Wextra)
    # Link with pthread and other common Linux libraries
    find_package(Threads REQUIRED)
endif()

find_package(libuv CONFIG REQUIRED)
find_package(unofficial-utf8proc CONFIG REQUIRED)

add_library(cstomp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cstomp.c)

# Set target properties
set_target_properties(cstomp PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

target_link_libraries(cstomp PUBLIC
    libuv::uv
    utf8proc)

# Platform-specific linking
if(UNIX AND NOT APPLE)
    target_link_libraries(cstomp PRIVATE Threads::Threads)
elseif(WIN32)
    # Windows-specific libraries that might be needed
    target_link_libraries(cstomp PRIVATE ws2_32 iphlpapi userenv)
endif()

# Include directories
target_include_directories(cstomp 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Installation rules
include(GNUInstallDirs)

install(TARGETS cstomp
    EXPORT cstompTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/ 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Export configuration
install(EXPORT cstompTargets
    FILE cstompTargets.cmake
    NAMESPACE cstomp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cstomp)

# Create config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    cstompConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cstompConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cstompConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cstomp)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cstompConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cstompConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cstomp)

# Add subdirectories
add_subdirectory(example)
add_subdirectory(test)
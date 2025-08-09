# CSTOMP - Simple Text Oriented Messaging Protocol Client Library

A lightweight C library for connecting to and communicating with STOMP message brokers. This library provides asynchronous I/O operations using libuv and supports STOMP protocol version 1.1.

## Features

- **Asynchronous I/O**: Built on libuv for high-performance, non-blocking operations
- **STOMP 1.1 Protocol**: Full support for STOMP version 1.1 specification
- **Connection Management**: Easy connection setup with authentication support
- **Message Sending**: Send messages to queues and topics
- **Callback System**: Flexible callback system for handling events
- **Error Handling**: Comprehensive error codes and handling

## Dependencies

- **libuv**: For asynchronous I/O operations
- **C Standard Library**: Standard C libraries (stdio, stdlib, string)

## Installation

0. Windows vcpkg installation
    ```bash
    $ git clone https://github.com/microsoft/vcpkg.git
    $ ./bootstrap-vcpkg.bat # for powershell
    $ ./bootstrap-vcpkg.sh # for bash
    ```

make sure to create an environment variable VCPKG_ROOT that stores the path that vcpkg was cloned to
also consider adding vcpkg to your path. otherwise you will have to call vcpkg using a relative or absolute path

### Option 1: Using CMake (Recommended)

The library provides CMake integration for easy inclusion in your projects.

#### Building and Installing

1. **Install dependencies:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libuv1-dev cmake
   
   # macOS with Homebrew
   brew install libuv cmake
   
   # Windows with vcpkg
   vcpkg install libuv
   ```

2. **Build and install the library:**
   ```bash
   git clone https://github.com/yourusername/cstomp.git
   cd cstomp
   mkdir build && cd build
   cmake ..
   make
   sudo make install  # On Windows: cmake --build . --target install
   ```

#### Using CSTOMP in Your CMake Project

Once installed, you can easily use CSTOMP in your CMake projects:

```cmake
cmake_minimum_required(VERSION 3.12)
project(my_stomp_app)

# Find the installed CSTOMP library
find_package(cstomp REQUIRED)

# Create your executable
add_executable(my_app main.c)

# Link against CSTOMP
target_link_libraries(my_app PRIVATE cstomp::cstomp)
```

#### Using with vcpkg (Windows)

If using vcpkg on Windows:

```cmake
# Set vcpkg toolchain (if not set via environment)
set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")

find_package(cstomp REQUIRED)
target_link_libraries(my_app PRIVATE cstomp::cstomp)
```

### Option 2: Header-Only Usage

For simple projects, you can include the header directly:

1. **Install dependencies** (same as above)

2. **Include the header in your project:**
   ```c
   #include "cstomp.h"
   ```

3. **Compile with required libraries:**
   ```bash
   gcc your_program.c -luv -o your_program
   ```

### Option 3: Add as Subdirectory

Include CSTOMP directly in your project:

```cmake
# In your CMakeLists.txt
add_subdirectory(third_party/cstomp)
target_link_libraries(my_app PRIVATE cstomp)
```

## Quick Start

Here's a simple example of connecting to a STOMP broker and sending a message:

```c
#include "cstomp.h"
#include <stdio.h>

// Callback function called when connection is established
void on_connect(void *ctx) {
    printf("Connected to STOMP server!\n");
    
    // Send a message once connected
    cstomp_connection_t *connection = (cstomp_connection_t *)ctx;
    const char *message = "Hello, STOMP!";
    cstomp_send(connection, "/queue/test", message, strlen(message)); // or '/topic/test'
}

// Callback function called when data is received
void on_read(void *ctx, char *buffer, size_t nread) {
    printf("Received data: %.*s\n", (int)nread, buffer);
}

// Callback function called when data is sent
void on_write(void *ctx, char *buffer, size_t nwrote) {
    printf("Sent message: %.*s\n", (int)nwrote, buffer);
}

int main() {
    // Create a new connection
    cstomp_connection_t *connection = cstomp_connection();
    if (!connection) {
        fprintf(stderr, "Failed to create connection\n");
        return 1;
    }
    
    // Set up callbacks
    cstomp_set_connect_callback(connection, connection, on_connect);
    cstomp_set_read_callback(connection, NULL, on_read);
    cstomp_set_write_callback(connection, NULL, on_write);
    
    // Connect to STOMP server
    int result = cstomp_connect(connection, "localhost", 61613, "admin", "admin");
    if (result != CSTOMP_OK) {
        fprintf(stderr, "Connection failed with error: %d\n", result);
        cstomp_connection_free(connection);
        return 1;
    }
    
    // Clean up (this line won't be reached in this example as cstomp_connect blocks)
    cstomp_connection_free(connection);
    return 0;
}
```

## Common STOMP Brokers

This library works with popular STOMP brokers including:

- **Apache ActiveMQ**: Default port 61613
- **RabbitMQ**: With STOMP plugin, default port 61613
- **Apache Apollo**: Default port 61613
- **HornetQ/Artemis**: Default port 61613

## Documentation Generation

The library includes comprehensive documentation in the header file comments using Doxygen format. You can generate HTML documentation using Sphinx and the Breathe extension.

### Installing Sphinx

#### Ubuntu/Debian
```bash
# Install Python and pip if not already installed
sudo apt update
sudo apt install python3 python3-pip

# Install Sphinx and required extensions
pip3 install sphinx breathe
```

#### macOS
```bash
# Using Homebrew (install Homebrew first if needed from https://brew.sh)
brew install python3

# Install Sphinx and required extensions
pip3 install sphinx breathe

# Alternative: Using MacPorts
sudo port install py311-sphinx
sudo port select --set python3 python311
sudo port select --set sphinx py311-sphinx
```

#### Windows
```cmd
# Using pip (Python must be installed first from https://python.org)
pip install sphinx breathe

# Alternative: Using Chocolatey (install Chocolatey first)
choco install python
pip install sphinx breathe

# Alternative: Using conda/Anaconda
conda install sphinx
pip install breathe
```

### Generating Documentation

1. **Install Doxygen** (required by Breathe to parse C headers):

   **Ubuntu/Debian:**
   ```bash
   sudo apt install doxygen
   ```

   **macOS:**
   ```bash
   brew install doxygen
   ```

   **Windows:**
   ```cmd
   # Using Chocolatey
   choco install doxygen.install
   
   # Or download from: https://www.doxygen.nl/download.html
   ```

2. **Create documentation structure:**
   ```bash
   mkdir docs
   cd docs

   # project name: cstomp
   sphinx-quickstart
   ```

Create `docs/api.rst`:
```rst
API Reference
=============

.. doxygenfile:: cstomp.h
   :project: cstomp
```

And include it in your `docs/index.rst`:
```rst
.. toctree::
   :maxdepth: 2
   :caption: Contents:

   api
```

3. **Configure Sphinx** by editing `docs/conf.py`:
   ```python
   # Add extensions
   extensions = ['breathe']
   
   # Configure Breathe
   breathe_projects = {"cstomp": "../doxygen/xml"}
   breathe_default_project = "cstomp"
   ```

4. **Create Doxygen configuration** (`Doxyfile`):
   ```bash
   doxygen -g
   ```

   Edit the generated `Doxyfile`:
   ```
   INPUT = include/cstomp/cstomp.h
   GENERATE_HTML = NO
   GENERATE_XML = YES
   XML_OUTPUT = docs/doxygen/xml
   RECURSIVE = YES
   EXTRACT_ALL = YES
   ```

5. **Generate documentation:**
   ```bash
   # Create the output directory structure
   mkdir -p docs/doxygen/xml

   # Generate Doxygen XML
   doxygen
   
   # Generate HTML documentation with Sphinx
   cd docs
   make html
   ```

6. **View documentation:**
   Open `docs/_build/html/index.html` in your web browser.

## Contributing

This library is designed to be lightweight and focused on core STOMP functionality. When contributing:

1. Maintain the single-header design
2. Keep dependencies minimal
3. Follow existing code style
4. Add appropriate documentation

## License

Please refer to the license information in the source file.
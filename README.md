# building on windows

### install [vcpkg]
```bash
$ git clone https://github.com/microsoft/vcpkg.git
$ ./bootstrap-vcpkg.bat # for powershell
$ ./bootstrap-vcpkg.sh # for bash
```

make sure to create an environment variable VCPKG_ROOT that stores the path that vcpkg was cloned to
also consider adding vcpkg to your path. otherwise you will have to call vcpkg using a relative or absolute path

### install [libuv](https://github.com/libuv/libuv/tree/v1.x?tab=readme-ov-file#install-with-vcpkg) 
```bash
$ vcpkg install libuv
```

### install [utf8proc](https://github.com/JuliaStrings/utf8proc)
```bash
$ vcpkg install utf8proc
```

### install [cstomp](https://github.com/LoganKloft/cstomp)
```bash
$ git clone https://github.com/LoganKloft/cstomp.git
$ cmake -S . -B build
$ MSBuild.exe build/cstomp.vcpkg
```

# building documentation on windows


### install [sphinx](https://www.sphinx-doc.org/en/master/usage/installation.html#windows)
```bash
$ choco install sphinx
```
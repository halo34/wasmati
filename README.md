Article: [Wasmati: An efficient static vulnerability scanner for WebAssembly](https://www.sciencedirect.com/science/article/pii/S0167404822001407)
# Wasmati

This project aims to parse WAT and WASM files and get an AST, CFG and PDG.

## Building using CMake directly (Linux and macOS)

You'll need [CMake](https://cmake.org). You can then run CMake, the normal way:

```console
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
```

This will produce build files using CMake's default build generator. Read the CMake
documentation for more information.

**NOTE**: You must create a separate directory for the build artifacts (e.g. `build` above).

## Building using the top-level `Makefile` (Linux and macOS)

**NOTE**: Under the hood, this uses `make` to run CMake, which then calls `make` again.
On some systems (typically macOS), this doesn't build properly. If you see these errors,
you can build using CMake directly as described above.

You'll need [CMake](https://cmake.org). If you just run `make`, it will run CMake for you, 
and put the result in `out/clang/Debug/` by default:

> Note: If you are on macOS, you will need to use CMake version 3.2 or higher

```console
$ make
```

This will build the default version of the tools: a debug build using the Clang
compiler.

There are many make targets available for other configurations as well. They
are generated from every combination of a compiler, build type and
configuration.

 - compilers: `gcc`, `clang`, `gcc-i686`, `gcc-fuzz`
 - build types: `debug`, `release`
 - configurations: empty, `asan`, `msan`, `lsan`, `ubsan`, `no-tests`

They are combined with dashes, for example:

```console
$ make clang-debug
$ make gcc-i686-release
$ make clang-debug-lsan
$ make gcc-debug-no-tests
```

## Building (Windows)

You'll need [CMake](https://cmake.org). You'll also need
[Visual Studio](https://www.visualstudio.com/) (2015 or newer) or
[MinGW](http://www.mingw.org/).

_Note: Visual Studio 2017 and later come with CMake (and the Ninja build system)
out of the box, and should be on your PATH if you open a Developer Command prompt.
See <https://aka.ms/cmake> for more details._

You can run CMake from the command prompt, or use the CMake GUI tool. See
[Running CMake](https://cmake.org/runningcmake/) for more information.

When running from the commandline, create a new directory for the build
artifacts, then run cmake from this directory:

```console
> cd [build dir]
> cmake [wabt project root] -DCMAKE_BUILD_TYPE=[config] -DCMAKE_INSTALL_PREFIX=[install directory] -G [generator]
```

The `[config]` parameter should be a CMake build type, typically `DEBUG` or `RELEASE`.

The `[generator]` parameter should be the type of project you want to generate,
for example `"Visual Studio 14 2015"`. You can see the list of available
generators by running `cmake --help`.

To build the project, you can use Visual Studio, or you can tell CMake to do it:

```console
> cmake --build [wabt project root] --config [config] --target install
```

This will build and install to the installation directory you provided above.

So, for example, if you want to build the debug configuration on Visual Studio 2015:

```console
> mkdir build
> cd build
> cmake .. -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_INSTALL_PREFIX=..\ -G "Visual Studio 14 2015"
> cmake --build . --config DEBUG --target install
```
## Commands
```console
> ./bin/wasmati --help
usage: wasmati [options] filename

  Read a file in the WebAssembly binary format or text format, and produces its
  Code Property Graph to perform queries and find vulnerabilities in the code.


options:
      --help                                  Print this help message
      --version                               Print version information
  -v, --verbose                               Output information about the generation of Code Property Graph
  -o, --output=FILENAME                       Output file for vulnerability report, by default use stdout
  -d, --dot-output=FILENAME                   Serialize the graph as dot.
  -D, --datalog=DIRECTORY                     Serialize the graph as a souffl� datalog program, facts are csv files (node.facts and edge.facts files).
  -s, --csv-output=FILENAME                   Serialize the graph as csv file.
  -j, --json-output=FILENAME                  Serialize the graph as JSON file.
  -c, --config=FILENAME                       JSON configuration file.
      --graph                                 Treat input file as a serialised graph.
      --wat                                   Treat input file as a wat file.
      --wasm                                  Treat input file as a wasm file.
  -f, --function=FUNCTIONNAME                 Output file for the given function.
  -i, --info                                  Print time information of the generation of CPG.
  -l, --loop=LOOPNAME                         Print all information during generation of CPG.
      --enable-exceptions                     Enable Experimental exception handling
      --disable-mutable-globals               Disable Import/export mutable globals
      --enable-saturating-float-to-int        Enable Saturating float-to-int operators
      --enable-sign-extension                 Enable Sign-extension operators
      --enable-simd                           Enable SIMD support
      --enable-threads                        Enable Threading support
      --enable-multi-value                    Enable Multi-value
      --enable-tail-call                      Enable Tail-call support
      --enable-bulk-memory                    Enable Bulk-memory operations
      --enable-reference-types                Enable Reference types (anyref)
      --enable-annotations                    Enable Custom annotation syntax
      --enable-all                            Enable all features
      --ignore-custom-section-errors          Ignore errors in custom sections
      --no-check                              Don't check for invalid modules
      --native                                Execute native queries.
      --ast                                   Output the Abstract Syntax Tree
      --cfg                                   Output the Control Flow Graph
      --pdg                                   Output the Program Dependence Graph
      --cg                                    Output the Call Graph
```
# Building using Docker
Wasmati can be build and run in a docker compiler. For this you will need to have [Docker](https://www.docker.com/) installed.

The first thing to do is to build the container using the Dockerfile. In the root of the project just run:
```console
$ docker build -t wasmati .
```
This will create a docker image with a tag `wasmati`. After build is completed you can run the tool using the command:
```console
$ docker run -t wasmati [arguments]
```
You can also mount shared folders with the host by using the option `-v` and use as input files thar are in the host. For instance, the file example `example.wasm` is in the host with the path `<host_directory>/example.wasm`
```console
$ docker run -v <host_directory>:/work -t wasmati /work/example.wasm -d /work/example.csv
```


# Code Profiler Based on Frida

This repository contains the code to profile LIEF functions with Frida.

## Get Started

Make sure to download the right version of [frida-gum](https://github.com/frida/frida/releases)
associated with your system/architecture.
On Linux it would be ``frida-gum-devkit-14.2.13-linux-x86_64.tar.xz``.

You also need to download (or compile) the SDK of LIEF (See: https://lief.quarkslab.com/packages/sdk/ for the
latest version).

Then you can compile the profiler as follows:

```bash
$ mkdir -p build && cd build
$ cmake .. \
    -DLIEF_DIR=<PATH>/LIEF-0.12.0-Linux-x86_64/share/LIEF/cmake \
    -DFRIDA_LIBS=<PATH>/frida-gum/libfrida-gum.a \
    -DFRIDA_INCLUDE_DIRS=<PATH>/frida-gum/
$ make
```

Running ``frida_profiler`` should output something like:

```bash
$ ./frida_profiler /usr/lib/libQt5WebEngineCore.so.5.15.2
LIEF::ELF::Parser::parse_segments<LIEF::ELF::ELF64> ran in 64 ms
LIEF::ELF::Parser::init ran in 278 ms
```






# libetw
Simple C++ library for Windows ETW event access

## Work in progress

The process and tcp events from the kernel provider are working, but the rest are work in progress.

## Build With Tests
```
mkdir build
cd build
set MAKE_TESTS=1
set GTEST_DIR=/c/Users/Devo/gtest
cmake -G "Visual Studio 14 Win64" ..
```

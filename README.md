# libetw
Simple C++ library for Windows ETW event access

## Features
 - Kernel Processes and Tcp Events
 - Dns Addresses

## Work in progress

The IPC, FileIO Volume are a work in progress.

## Build With Tests
```
mkdir build
cd build
set MAKE_TESTS=1
set GTEST_DIR=/c/Users/Devo/gtest
cmake -G "Visual Studio 14 Win64" ..
```

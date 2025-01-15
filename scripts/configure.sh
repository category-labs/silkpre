#!/bin/bash

cmake \
  -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
  -B build \
  -DCMAKE_BUILD_TYPE=Debug 

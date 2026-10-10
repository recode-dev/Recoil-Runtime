#!/bin/sh
set -e
g++ -std=c++17 -w -O1 -ffunction-sections -fdata-sections -DRCL_HOST_TEST -ISources \
    -o host_scan tools/host_scan.cpp \
    Sources/rcl_classdump.cpp Sources/rcl_deep.cpp Sources/rcl_macho.cpp Sources/rcl_scan.cpp \
    Sources/rcl_names_live.cpp Sources/rcl_log.cpp Sources/rcl_ident.cpp Sources/rcl_report.cpp \
    Sources/rcl_docgen.cpp Sources/rcl_live.cpp -Wl,--gc-sections

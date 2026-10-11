TARGET := iphone:clang:latest:15.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME := RecoilRuntime

RecoilRuntime_FILES := $(shell find src -name "*.cpp" -o -name "*.mm" | sort)

RECOIL_INC := -Isrc -Isrc/core -Isrc/scan -Isrc/utils
RecoilRuntime_CFLAGS := $(RECOIL_INC) -O2 -std=c++17 -fvisibility=hidden
RecoilRuntime_CXXFLAGS := $(RECOIL_INC) -O2 -std=c++17 -fvisibility=hidden
RecoilRuntime_OBJCFLAGS := $(RECOIL_INC) -O2 -fvisibility=hidden
RecoilRuntime_FRAMEWORKS := UIKit Foundation
RecoilRuntime_INSTALL_PATH := /usr/lib

include $(THEOS_MAKE_PATH)/library.mk

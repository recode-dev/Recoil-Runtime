# Recoil-Runtime - Theos project that builds the runtime offset searcher as a .dylib.
#
#   THEOS=/path/to/theos make            # build
#   THEOS=/path/to/theos make clean
#
# Output lands in .theos/obj/... as a .dylib. See .github/workflows/build.yml for the CI that
# installs Theos and builds this on a macOS runner.

export ARCHS ?= arm64        # LiveContainer-safe slice; use ARCHS="arm64 arm64e" for a fat jailbreak build
export TARGET = iphone:clang:latest:14.0
export ADDITIONAL_CFLAGS = -I Sources

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = RecoilRuntime

RecoilRuntime_FILES = \
    Sources/rcl_main.cpp \
    Sources/rcl_scan.cpp \
    Sources/rcl_hook.cpp \
    Sources/rcl_report.cpp \
    Sources/rcl_log.cpp

RecoilRuntime_CFLAGS     = -I Sources -O2 -fvisibility=hidden
RecoilRuntime_CXXFLAGS   = -I Sources -O2 -std=c++17 -fvisibility=hidden
RecoilRuntime_FRAMEWORKS = Foundation
RecoilRuntime_INSTALL_PATH = /usr/lib

include $(THEOS_MAKE_PATH)/library.mk

# Convenience: copy the built dylib to the repo root and the host build next to it.
after-all::
	@find .theos -name '$(LIBRARY_NAME)*.dylib' -exec cp {} ./$(LIBRARY_NAME).dylib \; 2>/dev/null || true
	@ls -la ./$(LIBRARY_NAME).dylib 2>/dev/null || echo "dylib not found - check .theos"

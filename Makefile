ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = RecoilRuntime
RecoilRuntime_FILES = Sources/rcl_main.cpp Sources/rcl_scan.cpp Sources/rcl_report.cpp Sources/rcl_log.cpp Sources/rcl_ident.cpp Sources/rcl_live.cpp Sources/rcl_classdump.cpp Sources/rcl_docgen.cpp Sources/rcl_macho.cpp Sources/rcl_deep.cpp Sources/rcl_hook.cpp Sources/rcl_alert.mm
RecoilRuntime_CFLAGS = -ISources -O2 -std=c++17 -fvisibility=hidden
RecoilRuntime_CXXFLAGS = -ISources -O2 -std=c++17 -fvisibility=hidden
RecoilRuntime_FRAMEWORKS = UIKit Foundation
RecoilRuntime_OBJCFLAGS = -ISources -O2 -fvisibility=hidden
RecoilRuntime_INSTALL_PATH = /usr/lib
ADDITIONAL_CXXFLAGS = -std=c++17

include $(THEOS_MAKE_PATH)/library.mk

after-all::
	@f=$$(find .theos -name '$(LIBRARY_NAME).dylib' | head -1); \
	if [ -n "$$f" ]; then cp -f "$$f" ./$(LIBRARY_NAME).dylib; ls -la ./$(LIBRARY_NAME).dylib; \
	else echo "build produced no dylib"; exit 1; fi

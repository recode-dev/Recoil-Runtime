CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -I../Sources
SRC       = ../Sources/rcl_scan.cpp ../Sources/rcl_hook.cpp ../Sources/rcl_report.cpp ../Sources/rcl_log.cpp ../Sources/rcl_main.cpp
HDR       = ../Sources/rcl_scan.h ../Sources/rcl_hook.h ../Sources/rcl_report.h ../Sources/rcl_log.h ../Sources/rcl_main.cpp
rclscan: main.cpp $(SRC) $(HDR)
	$(CXX) $(CXXFLAGS) -o $@ main.cpp $(SRC)
clean:
	rm -f rclscan
.PHONY: clean

CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -lcrypto

SRC_COMMON = security_utils.cpp hmac.cpp
HDR_COMMON = security_utils.h hmac.h

all: logappend logread security_tests

logappend: logappend.cpp $(SRC_COMMON) $(HDR_COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

logread: logread.cpp $(SRC_COMMON) $(HDR_COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

security_tests: ../tests/security_tests.cpp $(SRC_COMMON) $(HDR_COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f logappend logread security_tests
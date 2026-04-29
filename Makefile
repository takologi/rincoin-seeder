CXXFLAGS = -O3 -g0 -march=native
LDFLAGS = $(CXXFLAGS)

# `rincoin.o` provides the version-handshake / address-relay logic that
# was historically called `bitcoin.o` upstream. Renamed for the Rincoin
# community fork; see rincoin.{h,cpp}.
dnsseed: dns.o rincoin.o netbase.o protocol.o db.o main.o util.o
	g++ -pthread $(LDFLAGS) -o dnsseed dns.o rincoin.o netbase.o protocol.o db.o main.o util.o -lcrypto

%.o: %.cpp *.h
	g++ -std=c++11 -pthread $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<

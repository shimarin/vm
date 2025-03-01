PREFIX ?= /usr/local
PYTHON ?= python3
CFLAGS=-std=c++20 `pkg-config --cflags libxml++-5.0`
LIBS=-liniparser -lsystemd -lsmartcols -lsquashfuse `pkg-config --libs libxml++-5.0`

all: vm.bin mirrortap.bin vm.so

vm.bin: vm.cpp json_messaging.cpp netif.cpp pci.cpp run_dir.cpp usb.cpp
	g++ -D__USE_REAL_MAIN__ -o $@ $^ $(CFLAGS) $(LIBS)

vm.so: vm.cpp json_messaging.cpp netif.cpp pci.cpp run_dir.cpp
	g++ -std=c++20 -g -shared -fPIC -o $@ $^

mirrortap.bin: mirrortap.cpp
	g++ -std=c++20 -o $@ $^

repl.bin: repl.cpp netif.cpp pci.cpp run_dir.cpp
	g++ -g -std=c++23 -o $@ $^ `$(PYTHON) -m pybind11 --includes` `$(PYTHON)-config --embed --libs`

install: all
	install -Dm755 vm.bin $(DESTDIR)$(PREFIX)/bin/vm
	install -Dm755 mirrortap.bin $(DESTDIR)$(PREFIX)/bin/mirrortap

clean:
	rm *.bin *.so

PREFIX ?= /usr/local

all: vm vm.so

vm: *.cpp
	g++ -std=c++20 -D__USE_REAL_MAIN__ -o $@ $^ -liniparser4 -lsystemd -lsmartcols -lsquashfuse

vm.so: *.cpp
	g++ -std=c++20 -g -shared -fPIC -o $@ $^

install: all
	install -Dm755 vm $(DESTDIR)$(PREFIX)/bin/vm

clean:
	rm vm vm.so


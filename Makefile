PREFIX ?= /usr/local

all: vm.bin mirrortap.bin vm.so

vm.bin: vm.cpp json_messaging.cpp netif.cpp
	g++ -std=c++20 -D__USE_REAL_MAIN__ -o $@ $^ -liniparser -lsystemd -lsmartcols -lsquashfuse

vm.so: vm.cpp json_messaging.cpp
	g++ -std=c++20 -g -shared -fPIC -o $@ $^

mirrortap.bin: mirrortap.cpp
	g++ -std=c++20 -o $@ $^

install: all
	install -Dm755 vm.bin $(DESTDIR)$(PREFIX)/bin/vm
	install -Dm755 mirrortap.bin $(DESTDIR)$(PREFIX)/bin/mirrortap

clean:
	rm *.bin *.so


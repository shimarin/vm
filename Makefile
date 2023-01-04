all: vm vm.so

vm: *.cpp
	g++ -std=c++20 -D__USE_REAL_MAIN__ -o $@ $^ -liniparser4 -lsystemd -lcrypto -lsmartcols

vm.so: *.cpp
	g++ -std=c++20 -g -shared -fPIC -o $@ $^

install: all
	cp -a vm /usr/local/bin/

clean:
	rm vm vm.so


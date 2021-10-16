all: vm

vm: vm.cpp
	g++ -std=c++20 -o $@ $< -liniparser4

install: all
	cp -a vm /usr/local/bin/

clean:
	rm vm


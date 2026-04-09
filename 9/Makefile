.PHONY: test clean safe_read_byte.o

CC_FLAGS=-O2 -Wno-unused-result -std=c++17

test: safe_read_byte.o
	g++ ${CC_FLAGS} safe_read_byte.o test.cpp -o test.out

safe_read_byte.o:
	g++ ${CC_FLAGS} -c safe_read_byte.cpp

clean:
	rm *.o *.out
.PHONY: test pools.o sigsegv_handler.o clean

CC_FLAGS=-std=c++17 -O2 -Wno-unused-result -pthread

test: sigsegv_handler.o pools.o
	g++ ${CC_FLAGS} pools.o sigsegv_handler.o test.cpp -o test.out

pools.o:
	g++ ${CC_FLAGS} -c pools.cpp

sigsegv_handler.o:
	g++ ${CC_FLAGS} -c sigsegv_handler.cpp

clean:
	rm *.o *.out
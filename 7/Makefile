.PHONY: test pools.o sigsegv_handler.o clean

test: sigsegv_handler.o pools.o
	g++ -O2 -Wno-unused-result -pthread pools.o sigsegv_handler.o test.cpp -o test.out

pools.o:
	g++ -O2 -Wno-unused-result -pthread -c pools.cpp

sigsegv_handler.o:
	g++ -O2 -Wno-unused-result -pthread -c sigsegv_handler.cpp

clean:
	rm *.o *.out
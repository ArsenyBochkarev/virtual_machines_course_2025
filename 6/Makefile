.PHONY: test pool.o clean

test: pool.o
	g++ -O2 pool.o test.cpp -o test.out

pool.o:
	g++ -O2 -c pool.cpp

clean:
	rm *.o *.out
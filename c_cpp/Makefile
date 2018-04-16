diff_func: c_test.o cpp_test.o
	nm c_test.o
	nm cpp_test.o

%.o: %.cc
	g++ --std=c++11 -o $@ -c $<

%.o: %.c
	gcc -o $@ -c $<

clean:
	rm *.o

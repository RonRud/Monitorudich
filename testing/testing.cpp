
#include <iostream>
#include <tuple>
#include <string>
#include <windows.h>
#include <stdarg.h>

void test() {};
#define test(...) foo(__VA_ARGS__)

typedef void* (*general_func)(...);

int addition(int x, int y, int z) {
    std::cout << x+y+z << std::endl;
    return x;
}

template <typename T>
void get_details(T x) {
    std::cout << "The type is: "  << typeid(x).name() << " , the value is: " << x << std::endl;
    return;
}
template <typename T, typename ... Args>
void get_details(T t, Args... args) {
    get_details(t);
    get_details(args...);
    return;
}

template <typename ... Args>
void foo(Args... args) {
    general_func x = (general_func) &addition;
    get_details(args...);
    //x(args...);
}

/*
void test(...) {
    va_list args;
    foo(args);
}
*/

int32_t main(int argc, char** argv) {
    DWORD x=2,y=3,z=9;
    foo(1, 2, 3);
    foo(x, y, z);
    foo(&addition);
    foo(&test);
    void* asd = (void*)&test; 
    test("z",8.5);

// Doesn't work
    UINT_PTR funcPtr = (DWORD)(void*)test;
	general_func testFunc = (general_func)funcPtr;
    testFunc("n",9.7,"wha");

    //foo(1.1, 2.2);
    //foo("1", "2");
    return EXIT_SUCCESS;
}
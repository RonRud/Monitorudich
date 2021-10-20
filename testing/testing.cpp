
#include <iostream>
#include <tuple>
#include <string>

typedef void* (*general_func)(...);

int addition(int x, int y, int z) {
    std::cout << x+y+z << std::endl;
    return x;
}

//TODO need to check if this works with microsoft types!!!!!!!!!!!!!!
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
    x(args...);
}

int32_t main(int argc, char** argv) {
    foo(1, 2, 3);
    foo(5, 9, 3);
    //foo(1.1, 2.2);
    //foo("1", "2");
    return EXIT_SUCCESS;
}
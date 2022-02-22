#include <iostream>
#include <windows.h>
using namespace std;

int main() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 2);
    int t1 = 0, t2 = 1, nextTerm = 0;
    cout << "Fibonacci Series: ";

    for (int i = 0; i < 10000;i++) {
        nextTerm = t1 + t2;
        t1 = t2;
        t2 = nextTerm;

        cout << nextTerm << ", ";
    }
    return 0;
}
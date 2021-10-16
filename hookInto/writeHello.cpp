#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

int main() {
    std::string input;
    std::cin >> input;

    LPSTR x = "shnitzel";
    LPSTR y = "shnitzel";
    if(0 == lstrcmpA(x,y)) {std::cout << "wha a shnitzel" << std::endl;}
    std::ofstream writeFile("out.txt");
    writeFile << input;
    writeFile.close();

    std::cin >> input;
}
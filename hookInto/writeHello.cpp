#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

int main() {
    std::string input;
    std::cin >> input;

    //LPSTR x = TEXT("shnitzel");
    //LPSTR y = L"shnitzel";
    if(0 == lstrcmpA("shnitzel", "shnitzel")) {std::cout << "wha a shnitzel" << std::endl;}
    std::ofstream writeFile("out.txt");
    writeFile << input;
    writeFile.close();

    std::cin >> input;
}
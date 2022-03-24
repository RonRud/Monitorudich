#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <stdlib.h>

int main() {
    std::string input;
    std::cin >> input;

    system("echo Let's see if you can read this\n");
    //LPSTR x = TEXT("shnitzel");
    //LPSTR y = L"shnitzel";
    if(0 == lstrcmpA("shnitzel", "shnitzel")) {std::cout << "wha a shnitzel" << std::endl;}
    std::ofstream writeFile("out.txt");
    writeFile << input;
    writeFile.close();

    std::cin >> input;
}
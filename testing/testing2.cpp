/*
#include <iostream>

template <typename T>
typedef T (*general_func)(...);

int addition(int x, int y, int z) {
    std::cout << x+y+z << std::endl;
    return x;
}
int byPass(int x, int y, int z) {

}


int32_t main(int argc, char** argv) {
    general_func asd = (general_func)&addition;
    int x = asd(5,3,8); 
*/

#include <windows.h>
#include <memory>
#include <iostream>

#define JMPTO(From, To) (TO) - (FROM) - 5
/*
void __declspec(naked) Hook() {
    __asm {
        MOV EAX, 0x7B0
        RETN 14
    }; 
}*/

void __declspec(naked) Hook() {
    std::cout << "Wha hooked" << std::endl;
    __asm {
        //MOV EDI,EDI
        POP EAX
        PUSH EBP
        PUSH EAX
        lea EBP,[ESP+4]
        RETN
    };
}

bool Test(int x, int y) {
    std::cout << "This is the only thing printed:" << x+y << std::endl;
    return true;
}

void inlineHookFunction(DWORD Function)
{ 
    DWORD Old;
    DWORD n;
    DWORD numBytes = 5;
    VirtualProtect((void*)Function, 5, PAGE_EXECUTE_READWRITE, &Old);
    //*(BYTE *)Function = 0xE9; //JMP Opcode
    *(BYTE *)Function = 0xE8; //call Opcode
    *(DWORD *)(Function+1) = (DWORD)Hook - (DWORD)Function - 5;//Calculate amount of bytes to jmp
    VirtualProtect((void*)Function, 5, Old, &n);
    //That's it...hooked.
}

int main() {
    if(Test(5,3)) {
        std::cout << "1st works" << std::endl;
    }
    inlineHookFunction((DWORD)Test);
    if(Test(5,3)) {
        std::cout << "2nd works" << std::endl;
    }
}



/*
BOOL DllMain(__in HINSTANCE hinstDLL,__in DWORD fdwReason,__in LPVOID 
lpvReserved)
{
 if (fdwReason == DLL_PROCESS_ATTACH)
 {
 //inlineHookFunction();
 }
}
*/
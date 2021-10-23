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

DWORD hookAddress;

void __declspec(naked) Hook() {
    /*
    //prolog
    __asm {
        push ebp ; Save ebp
        mov ebp, esp ; Set stack frame pointer
        push eax
        push ebx
        push ecx
    }*/
    std::cout << "Wha hooked" << std::endl;
    DWORD originFuncAddr;
    __asm {
        //lea ecx, originFuncAddr
        MOV EDI, EDI
        POP EAX
        PUSH EBP
        PUSH EAX
        lea EBP,[ESP+4]
        //MOV EBP, ESP
        RETN
    };
    /*
    DWORD returnJmpAddress = hookAddress - 
    __asm {
        jmp 
    }*/
    /*
    //epilog
    __asm {
        pop ecx
        pop ebx
        pop eax
        mov esp, ebp
        pop ebp
        ret
    }*/
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
    if (*(BYTE*)Function == 0xE9) {
        Function += *(int*)(Function + 1) + 5;
    }
    VirtualProtect((void*)Function, 5, PAGE_EXECUTE_READWRITE, &Old);
    //*(BYTE *)Function = 0xE9; //JMP Opcode
    *(BYTE *)Function = 0xE8; //call Opcode
    *(DWORD *)(Function+1) = (DWORD)Hook - (DWORD)Function - 5;//Calculate amount of bytes to jmp
    VirtualProtect((void*)Function, 5, Old, &n);
    //That's it...hooked.
}

int main() {
    hookAddress = (DWORD)Hook;
    if(Test(5,3)) {
        std::cout << "1st works" << std::endl;
    }
    inlineHookFunction((DWORD)Test);
    if(Test(5,3)) {
        std::cout << "2nd works" << std::endl;
    }
    std::cout << "reached the end" << std::endl;
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
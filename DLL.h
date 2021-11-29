#ifndef _DLL_H_
#define _DLL_H_

#pragma comment(lib,"user32.lib")
 
#include <windows.h>
#include<conio.h>
#include<iostream>
#include<string>
#include <map>
#include <fstream>
#include <vector>

//#define TARGET_FUNCTION "WriteFile"
#define TARGET_FUNCTION "lstrcmpA"
#define IMPORT_TABLE_OFFSET 1
using namespace std;

BOOL newWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

bool inlineHookFunction(DWORD Function, std::string* functionName);
void Hook();

DWORD sourceAddr;
DWORD originFuncAddr;
std::map<DWORD, std::string*> addressToNameMap;

int functionParamsNum;
bool foundWINAPICleanup;
DWORD functionParameters[50];

//saved values from within the hooked function
DWORD savedEax;
DWORD savedEbx;
DWORD savedEcx;
DWORD savedEdx;
DWORD beforeFunctionEsp;
DWORD beforeFunctionEbp;

//int newlstrcmpA();
int WINAPI newlstrcmpA(LPCSTR a,LPCSTR b);
bool IAThooking(HMODULE, LPCSTR); //,PVOID);
bool rewriteThunk(PIMAGE_THUNK_DATA pThunk,void* newFunc);
PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE);
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved);

 
#endif /* _DLL_H_ */
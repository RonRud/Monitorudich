#ifndef _DLL_H_
#define _DLL_H_

#pragma comment(lib,"user32.lib")
 
#include <windows.h>
#include <conio.h> //check if this header is needed
#include <iostream>
#include <string>
#include <map>
#include <fstream>
#include <vector>

#define IMPORT_TABLE_OFFSET 1

BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved);

bool inlineHookFunction(DWORD Function, std::string* functionName);
void Hook();

const char loggerFilePath[] = "C:\\Users\\Rudic\\source\\repos\\RonRud\\Monitorudich\\logger_output.txt";

DWORD originFuncAddr;
std::map<DWORD, std::string*> addressToNameMap;

int functionParamsNum;
bool foundWINAPICleanup;
DWORD functionParameters[50];

int i;

//saved values from within the hooked function
DWORD savedEax;
DWORD savedEbx;
DWORD savedEcx;
DWORD savedEdx;
DWORD beforeFunctionEsp;
DWORD beforeFunctionEbp;

bool IAThooking(HMODULE);
void IAThookingCleanup();
void inlineHookFunctionCleanup(DWORD functionAddr);

PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE);

#endif /* _DLL_H_ */
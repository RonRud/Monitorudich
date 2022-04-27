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
void IAThookingCleanup();
void inlineHookFunctionCleanup(DWORD functionAddr);

// Functions that are part of the hook procedure (ran at runtime)
void Hook();
void logHookName();
void logAdditionalVariables();
void getStack();
void logStack();
void accountForTrampolineHookInOriginFuncAddr();
void avoidFunctionLogsCreatedByTheHook();


char loggerFilePath[100];
char infoToMainFilePath[100];
char infoFromMainFilePath[100];
char offlineScrapesFile[100];
char blacklistFilePath[100];
char webScrapperPythonFilePath[100];
char executablePath[100];
char dllFunctionsLoggerPath[100];

int MAX_STACK_TO_SHOW = 8;
DWORD originFuncAddr;
std::map<DWORD, std::string*> addressToNameMap;
std::map<DWORD, DWORD> trampolineLocationToFunctionLocation;
std::map<DWORD, DWORD> trampolineLocationToFunctionLocationDsOffset;
std::vector<std::pair<DWORD, DWORD>> myFunctionsStartAndEndAddressesVector;

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

bool IAThooking(HMODULE, int attamptToHookNumFunctions);
void IAThookingCleanup();
void inlineHookFunctionCleanup(DWORD functionAddr);

PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE);

bool isWebScrapingEnabled;
std::map<std::string*, std::string*> nameToDocumantationString;

#endif /* _DLL_H_ */
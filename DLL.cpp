#include "DLL.h"
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH: {
		IAThooking(GetModuleHandleA(NULL), TARGET_FUNCTION);//,newWriteFile); //newlstrcmpA);
		//initialize an empty file
		std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::trunc);
		saveFile.close();
		break;
	}
	case DLL_PROCESS_DETACH:
		//IAThooking(GetModuleHandleA(NULL), TARGET_FUNCTION);//,(void *)sourceAddr);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return true;
}
bool IAThooking(HMODULE hInstance, LPCSTR targetFunction) //,PVOID newFunc)
{
	bool flag = false;

	PIMAGE_IMPORT_DESCRIPTOR importedModule;
	PIMAGE_THUNK_DATA pFirstThunk, pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME pFuncData;

	importedModule = getImportTable(hInstance);
	//pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hInstance, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize); - You can just call this function to get the Import Table
	while (*(WORD*)importedModule != 0) //over on the modules (DLLs)
	{
		printf("\n%s:\n---------\n", (char*)((PBYTE)hInstance + importedModule->Name));//printing Module Name
		pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->FirstThunk);//pointing to its IAT
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->OriginalFirstThunk);//pointing to OriginalThunk
		pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);// and to IMAGE_IMPORT_BY_NAME
		while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0) //moving over IAT and over names' table
		{
			printf("%X %s\n", pFirstThunk->u1.Function, pFuncData->Name);//printing function's name and addr
			
			std::vector<const char*> blackList = { "EnterCriticalSection", "LeaveCriticalSection", "HeapFree", "HeapAlloc", //8B = mov function crushes
				"GetLastError", "SetLastError", "WriteFile", "GetProcessHeap", //FF 25 = call function crushes
			//from here these are excludes from runtime problems 	
			"MultiByteToWideChar", "free", "malloc"};
			bool shouldHook = true;
			for (const char* name : blackList) {
				if (strcmp(name, (char*)pFuncData->Name) == 0) {
					shouldHook = false;
					std::cout << "Blacklisted, not hooked" << std::endl << std::endl;
					break;
				}
			}
			//std::cout << "function name check: " << *addressToNameMap[pFirstThunk->u1.Function] << std::endl;
			if(strcmp(targetFunction,(char*)pFuncData->Name)==0)//checks if we are in the Target Function
			{
			if (shouldHook) {
				bool isHooked = inlineHookFunction(pFirstThunk->u1.Function, new std::string(pFuncData->Name));
				if (isHooked) {
					std::cout << "Hooked function successfully" << std::endl;
				}
				else {
					std::cout << "Didn't Hook function" << std::endl;
				}
				std::cout << std::endl;
			}
			/*
			if(rewriteThunk(pFirstThunk,newFunc))
				printf("Hooked %s successfully :)\n",targetFunction);
			*/
			}
			pOriginalFirstThunk++; // next node (function) in the array
			pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);
			pFirstThunk++;// next node (function) in the array
		}
		importedModule++; //next module (DLL)
	}
	return false;
}

/*
__declspec( naked ) int newlstrcmpA()
{
	_asm{
		XOR eax,eax;
		RETN 8;
	}
}

typedef BOOL (*WriteFuncPtr)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

BOOL newWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	MessageBoxA(NULL,"hook called","hehe",MB_OK);
	UINT_PTR funcPtr = sourceAddr;
	WriteFuncPtr writingFunc = (WriteFuncPtr)funcPtr;
	writingFunc(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	return 0;
};

int WINAPI newlstrcmpA(LPCSTR a,LPCSTR b)
{
	MessageBoxA(NULL,"hook called","hehe",MB_OK);
	return 0;
}
*/

void logHookName() {
	std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::app);
	saveFile << "name: " << *addressToNameMap[originFuncAddr-5] << ", ";
	saveFile << "address: " << originFuncAddr - 5 << ", ";
	//saveFile << std::endl;
	saveFile.close();
}

void logAdditionalVariables() {
	/*
	std::cout << "In findParamtersNum() " << "in function: " << *addressToNameMap[originFuncAddr - 5] << std::endl;
	__asm {
		mov edi, edi
		mov edi, edi
		mov edi, edi
		mov edi, edi
		mov edi, edi
		mov edi, edi
	}*/
	DWORD funcAddrPtr = originFuncAddr;
	std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::app);
	saveFile << "eax: " << savedEax << ", ";
	saveFile << "ebx: " << savedEbx << ", ";
	saveFile << "ecx: " << savedEcx << ", ";
	saveFile << "edx: " << savedEdx << ", ";
	saveFile << std::endl;

	//printf("%02X, ", *(BYTE*)funcAddrPtr);
	foundWINAPICleanup = false;
	while (*(BYTE*)(funcAddrPtr) != 0xC3 && *(BYTE*)(funcAddrPtr) != 0xCB) {
		//printf("%02X, ", *(BYTE*)funcAddrPtr);
		//if (strcmp("free", (char*)*addressToNameMap[originFuncAddr - 5]->c_str()) == 0) {
		//	printf("%02X", *(BYTE*)funcAddrPtr);
		//}
		if (*(BYTE*)(funcAddrPtr) == 0xC2) { //&& *(BYTE*)(funcAddrPtr+2)==0x00) {
			//std::cout << "found 0xC2 in if" << std::endl;
			//functionParamsNum = (int)*(BYTE*)(funcAddrPtr + 1);
			//functionParamsNum = (functionParamsNum + (functionParamsNum % 4)) / 4; // every stack entry is 4 bytes, makes sure all bytes are included by adding to a number divided by 4
			saveFile << "params bytes: " << functionParamsNum << ", ";
			foundWINAPICleanup = true;
			break;
		}
		funcAddrPtr++;
	}
	saveFile.close();
}

void __declspec(naked) logStack() {

	if (foundWINAPICleanup) {
		for (i = 0; i < functionParamsNum * 4; i += 4) { //start with an offset of 4 because the top of the stack is the return addr
			__asm {
				//lea eax, beforeFunctionEsp
				//add eax, i
				lea ecx, functionParameters
				add ecx, i
				add esp, i
				mov ebx, dword ptr[esp];
				mov[ecx], ebx
				
				mov esp, beforeFunctionEsp // reset esp to it's original value
			}	
		}
		__asm ret
	}
	__asm ret
}

void printStack() {
	for (int i = 0; i < functionParamsNum; i++) {
		std::cout << functionParameters[i] << ", ";
	}
	std::cout << std::endl;
}


void __declspec(naked) Hook() {
	/*
	//prologue
	__asm {
		push ebp ; Save ebp
		mov ebp, esp ; Set stack frame pointer
		push eax
		push ebx
		push ecx
	}*/
	__asm {
		//lea ecx, originFuncAddr
		mov savedEax, eax
		mov savedEbx, ebx
		mov savedEcx, ecx
		mov savedEdx, edx
		
		mov beforeFunctionEbp, ebp
		mov beforeFunctionEsp, esp
		
		POP EAX
		MOV originFuncAddr, EAX
	};
	logHookName();
	logAdditionalVariables();
	logStack();
	printStack();

	__asm {
		PUSH EBP
		PUSH originFuncAddr
		lea EBP, [ESP + 4]
	};

	__asm RETN
	/*
	DWORD returnJmpAddress = hookAddress -
	__asm {
		jmp
	}*/
	/*
	//epilogue
	__asm {
		pop ecx
		pop ebx
		pop eax
		mov esp, ebp
		pop ebp
		ret
	}*/
}


bool inlineHookFunction(DWORD functionAddr, std::string* functionName)
{
	DWORD Old;
	DWORD n;
	DWORD numBytes = 5;
	std::cout << "function addr: " << std::hex << functionAddr << std::endl;
	std::cout << "The first bytes of the function are: ";
	printf("%02X %02X %02X %02X %02X %02X", *(BYTE*)functionAddr, *(BYTE*)(functionAddr+1), *(BYTE*)(functionAddr+2), *(BYTE*)(functionAddr+3), *(BYTE*)(functionAddr+4), *(BYTE*)(functionAddr+5));
	std::cout << std::endl;
	if(*(BYTE*)functionAddr == 0x8B && *(BYTE*)(functionAddr + 1) == 0xFF) {

	} else if(*(BYTE*)functionAddr == 0xE9) {
		functionAddr += *(int*)(functionAddr + 1) + 5;
		return inlineHookFunction(functionAddr,functionName);
	} else if (*(BYTE*)functionAddr == 0xFF && *(BYTE*)(functionAddr + 1) == 0x25) { //TODO this is working very questionably at best
		DWORD dsOffsetOfFunction = *(DWORD*)(functionAddr + 2);

		__asm {
			push eax
			push ebx
			mov ebx, dsOffsetOfFunction
			mov eax, ds:[ebx]
			mov functionAddr, eax
			pop ebx
			pop eax
		}
		return inlineHookFunction(functionAddr,functionName);
		//need to check what the hell is in functionAddr
	}
	else {
		return false;
	}
	addressToNameMap[functionAddr] = functionName;
	VirtualProtect((void*)functionAddr, 5, PAGE_EXECUTE_READWRITE, &Old);
	//*(BYTE *)Function = 0xE9; //JMP Opcode
	*(BYTE*)functionAddr = 0xE8; //call Opcode
	*(DWORD*)(functionAddr + 1) = (DWORD)Hook - (DWORD)functionAddr - 5;//Calculate amount of bytes to jmp
	VirtualProtect((void*)functionAddr, 5, Old, &n);
	//That's it...hooked.
	return true;
}


PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hInstance)
{
	PIMAGE_DOS_HEADER dosHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;

	dosHeader = (PIMAGE_DOS_HEADER)hInstance;//cast hInstance to (IMAGE_DOS_HEADER *) - the MZ Header
	ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);//The PE Header begin after the MZ Header (which has size of e_lfanew)
	optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader); //Getting OptionalHeader
	dataDirectory = (IMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory[IMPORT_TABLE_OFFSET]);//Getting the import table of DataDirectory
	return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hInstance + dataDirectory.VirtualAddress);//ImageBase+RVA to import table

}
bool rewriteThunk(PIMAGE_THUNK_DATA pThunk, void* newFunc)
{
	DWORD CurrentProtect;
	DWORD junk;
	VirtualProtect(pThunk, 4096, PAGE_READWRITE, &CurrentProtect);//allow write to the page
	sourceAddr = pThunk->u1.Function;
	pThunk->u1.Function = (DWORD)newFunc; // rewrite the IAT to new function
	VirtualProtect(pThunk, 4096, CurrentProtect, &junk);//return previous premissions
	return true;
}
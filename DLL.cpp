#include "DLL.h"
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH: {
		//initialize an empty file
		std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::trunc);
		saveFile.close();

		IAThooking(GetModuleHandleA(NULL));
		break;
	}
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return true;
}
bool IAThooking(HMODULE hInstance)
{
	bool flag = false;

	PIMAGE_IMPORT_DESCRIPTOR importedModule;
	PIMAGE_THUNK_DATA pFirstThunk, pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME pFuncData;

	importedModule = getImportTable(hInstance);
	//pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hInstance, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize); - You can just call this function to get the Import Table
	while (*(WORD*)importedModule != 0) //over on the modules (DLLs)
	{
		if (strcmp((char*)((PBYTE)hInstance + importedModule->Name), (char*)"mscoree.dll") == 0) {
			std::cout << (char*)((PBYTE)hInstance + importedModule->Name) << "skipped" << std::endl;
			importedModule++;
			continue;
		}
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
			"MultiByteToWideChar"};//, "free", "malloc"}; they might be broken still
			bool shouldHook = true;
			for (const char* name : blackList) {
				if (strcmp(name, (char*)pFuncData->Name) == 0) {
					shouldHook = false;
					std::cout << "Blacklisted, not hooked" << std::endl << std::endl;
					break;
				}
			}

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
			pOriginalFirstThunk++; // next node (function) in the array
			pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);
			pFirstThunk++;// next node (function) in the array
		}
		importedModule++; //next module (DLL)
	}
	return false;
}

void logHookName() {
	std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::app);
	saveFile << "name: " << *addressToNameMap[originFuncAddr-5] << ", "; //gets the function's name from the table. The function address which is gathered from the stack 
																		 //has 5 more so it points to the instruction after the jmp in the function and not the function starting point.
	saveFile << "address: " << originFuncAddr - 5 << ", ";
	saveFile.close();
}

void logAdditionalVariables() {
	DWORD funcAddrPtr = originFuncAddr;
	std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::app);
	saveFile << "eax: " << savedEax << ", ";
	saveFile << "ebx: " << savedEbx << ", ";
	saveFile << "ecx: " << savedEcx << ", ";
	saveFile << "edx: " << savedEdx << ", ";

	foundWINAPICleanup = false;
	while (*(BYTE*)(funcAddrPtr) != 0xC3 && *(BYTE*)(funcAddrPtr) != 0xCB) {
		if (*(BYTE*)(funcAddrPtr) == 0xC2) { //&& *(BYTE*)(funcAddrPtr+2)==0x00) { add this if the parameters of winapi bug
			functionParamsNum = (int)*(BYTE*)(funcAddrPtr + 1);
			saveFile << "params bytes: " << functionParamsNum << ", ";
			functionParamsNum = (functionParamsNum + (functionParamsNum % 4)) / 4; // every stack entry is 4 bytes, makes sure all bytes are included by adding to a number divided by 4
			foundWINAPICleanup = true;
			break;
		}
		funcAddrPtr++;
	}
	if (foundWINAPICleanup == false) {
		functionParamsNum = (beforeFunctionEbp - beforeFunctionEsp) / 4; // gets all the stack between ebp of last function (before api function call) to the api function return address
																		 // this includes the stack parameters for the function and the local variables of the last function. 
		functionParamsNum--; // removes the two extra stack entries caused by the push of the return address of the api function and the hook function.
	}
	saveFile.close();
}

void __declspec(naked) getStack() {

	for (i = 0; i < functionParamsNum * 4; i += 4) {
		__asm {
			lea ecx, functionParameters
			add ecx, i
				
			add esp, 8 //adds an offset of 8 because the top of the stack is the return addr from this function, than the return address which called the api function
			add esp, i
			mov ebx, dword ptr[esp];
			mov[ecx], ebx
				
			mov esp, beforeFunctionEsp // reset esp to it's original value
		}	
	}
	__asm ret
}

void logStack() {
	std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::app);
	saveFile << "presumed function bytes in hex: ";
	for (int i = 0; i < functionParamsNum; i++) {
		saveFile << std::hex << functionParameters[i] << "-";
	}
	saveFile << ", ";
	saveFile << std::endl;
	saveFile.close();
}


void __declspec(naked) Hook() { // this means compiler doesn't go here
								// this function definition tells the compiler not to touch the stack
								// __declspecc(naked) means that there is no compiler setup of stack and therefor usage of local variables needs to be cleaned up manually
								// therfor all variables here are global 
	__asm {
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
	getStack();
	logStack();

	__asm {
		PUSH EBP
		PUSH originFuncAddr
		lea EBP, [ESP + 4]

		mov eax, savedEax
		mov ebx, savedEbx
		mov ecx, savedEcx
		mov edx, savedEdx
	};

	__asm RETN
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
	} else if (*(BYTE*)functionAddr == 0xFF && *(BYTE*)(functionAddr + 1) == 0x25) {
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
	}
	else {
		return false;
	}
	addressToNameMap[functionAddr] = functionName;
	VirtualProtect((void*)functionAddr, 5, PAGE_EXECUTE_READWRITE, &Old);
	*(BYTE*)functionAddr = 0xE8; //call Opcode
	*(DWORD*)(functionAddr + 1) = (DWORD)Hook - (DWORD)functionAddr - 5; //Calculate amount of bytes to jmp
	VirtualProtect((void*)functionAddr, 5, Old, &n);
	//That's it...hooked.
	//it only required a bit of satanic worship, only a couple things were sacrificed
	return true;
}


PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hInstance)
{
	std::cout << "IN PE Logger" << std::endl;
	std::ofstream saveFile("logger_output.txt", std::ios::out | std::ios::app);
	saveFile << "PE header extraction";
	saveFile << std::endl;
	saveFile.flush();
	if (saveFile.is_open()) {
		std::cout << "file opened" << std::endl;
	}
	else {
		std::cout << "file not opened" << std::endl;
	}
	
	// IMAGE_DOS_HEADER
	 PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hInstance;
	saveFile << "--DOS HEADER--" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_magic << "\t\tMagic number" << std::endl; //check if MZ
	saveFile << "\t0x" << std::hex << dosHeader->e_cblp << "\t\tBytes on last page of file" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_cp << "\t\tPages in file" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_crlc << "\t\tRelocations" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_cparhdr << "\t\tSize of header in paragraphs" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_minalloc << "\t\tMinimum extra paragraphs needed" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_maxalloc << "\t\tMaximum extra paragraphs needed" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_ss << "\t\tInitial (relative) SS value" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_sp << "\t\tInitial SP value" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_csum << "\t\tChecksum" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_ip << "\t\tInitial IP value" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_cs << "\t\tInitial (relative) CS value" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_lfarlc << "\t\tFile address of relocation table" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_ovno << "\t\tOverlay number" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_oemid << "\t\tOEM identifier (for e_oeminfo)" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_oeminfo << "\t\tOEM information; e_oemid specific" << std::endl;
	saveFile << "\t0x" << std::hex << dosHeader->e_lfanew << "\t\tFile address of new exe header" << std::endl;
	saveFile.flush();

	// IMAGE_NT_HEADERS
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)hInstance + dosHeader->e_lfanew); //the offset of the new technology header from the start of the file
	saveFile << "--NT HEADERS--" << std::endl;
	saveFile << "\t" << std::hex << "\t\tSignature" << imageNTHeaders->Signature << std::endl;

	// FILE_HEADER
	saveFile << "--FILE HEADER--" << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMachine" << imageNTHeaders->FileHeader.Machine << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tNumber of Sections" << imageNTHeaders->FileHeader.NumberOfSections << std::endl;
	saveFile << "\t0x" << std::hex << "\tTime Stamp" << imageNTHeaders->FileHeader.TimeDateStamp << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tPointer to Symbol Table" << imageNTHeaders->FileHeader.PointerToSymbolTable << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tNumber of Symbols" << imageNTHeaders->FileHeader.NumberOfSymbols << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize of Optional Header" << imageNTHeaders->FileHeader.SizeOfOptionalHeader << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tCharacteristics" << imageNTHeaders->FileHeader.Characteristics << std::endl;
	saveFile.flush();

	// OPTIONAL_HEADER
	saveFile << "--OPTIONAL HEADER--" << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMagic" << imageNTHeaders->OptionalHeader.Magic << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMajor Linker Version" << imageNTHeaders->OptionalHeader.MajorLinkerVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMinor Linker Version" << imageNTHeaders->OptionalHeader.MinorLinkerVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Code" << imageNTHeaders->OptionalHeader.SizeOfCode << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Initialized Data" << imageNTHeaders->OptionalHeader.SizeOfInitializedData << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of UnInitialized Data" << imageNTHeaders->OptionalHeader.SizeOfUninitializedData << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tAddress Of Entry Point (.text)" << imageNTHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tBase Of Code" << imageNTHeaders->OptionalHeader.BaseOfCode << std::endl;
	//saveFile << "\t0x" << std::hex << "\t\tBase Of Data" << imageNTHeaders->OptionalHeader.BaseOfData << std::endl; not sure why this was commented out
	saveFile << "\t0x" << std::hex << "\t\tImage Base" << imageNTHeaders->OptionalHeader.ImageBase << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSection Alignment" << imageNTHeaders->OptionalHeader.SectionAlignment << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tFile Alignment" << imageNTHeaders->OptionalHeader.FileAlignment << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMajor Operating System Version" << imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMinor Operating System Version" << imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMajor Image Version" << imageNTHeaders->OptionalHeader.MajorImageVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMinor Image Version" << imageNTHeaders->OptionalHeader.MinorImageVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMajor Subsystem Version" << imageNTHeaders->OptionalHeader.MajorSubsystemVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tMinor Subsystem Version" << imageNTHeaders->OptionalHeader.MinorSubsystemVersion << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tWin32 Version Value" << imageNTHeaders->OptionalHeader.Win32VersionValue << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Image" << imageNTHeaders->OptionalHeader.SizeOfImage << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Headers" << imageNTHeaders->OptionalHeader.SizeOfHeaders << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tCheckSum" << imageNTHeaders->OptionalHeader.CheckSum << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSubsystem" << imageNTHeaders->OptionalHeader.Subsystem << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tDllCharacteristics" << imageNTHeaders->OptionalHeader.DllCharacteristics << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Stack Reserve" << imageNTHeaders->OptionalHeader.SizeOfStackReserve << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Stack Commit" << imageNTHeaders->OptionalHeader.SizeOfStackCommit << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Heap Reserve" << imageNTHeaders->OptionalHeader.SizeOfHeapReserve << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tSize Of Heap Commit" << imageNTHeaders->OptionalHeader.SizeOfHeapCommit << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tLoader Flags" << imageNTHeaders->OptionalHeader.LoaderFlags << std::endl;
	saveFile << "\t0x" << std::hex << "\t\tNumber Of Rva And Sizes" << imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes << std::endl;
	saveFile.flush();

	// DATA_DIRECTORIES
	saveFile << "--DATA DIRECTORIES--" << std::endl;
	saveFile << "\tExport Directory Address: 0x" << std::hex << imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress << "; Size: 0x" << std::hex <<  imageNTHeaders->OptionalHeader.DataDirectory[0].Size << std::endl;
	saveFile << "\tImport Directory Address: 0x" << std::hex << imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress << "; Size: 0x" << std::hex << imageNTHeaders->OptionalHeader.DataDirectory[1].Size << std::endl;
	// TODO consider adding more data directories information
	
	// SECTION_HEADERS
	saveFile << "--SECTION HEADERS--" << std::endl;
	// get offset to first section header
	DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// print section data
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		saveFile << "\t" << sectionHeader->Name << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tVirtual Size" << sectionHeader->Misc.VirtualSize << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tVirtual Address" << sectionHeader->VirtualAddress << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tSize Of Raw Data" << sectionHeader->SizeOfRawData << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tPointer To Raw Data" << sectionHeader->PointerToRawData << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tPointer To Relocations" << sectionHeader->PointerToRelocations << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tPointer To Line Numbers" << sectionHeader->PointerToLinenumbers << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tNumber Of Relocations" << sectionHeader->NumberOfRelocations << std::endl;
		saveFile << "\t\t0x" << std::hex << "\t\tNumber Of Line Numbers" << sectionHeader->NumberOfLinenumbers << std::endl;
		saveFile << "\t\t0x" << std::hex << "\tCharacteristics" << sectionHeader->Characteristics << std::endl;

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize){
			PIMAGE_SECTION_HEADER importSection = sectionHeader;
			}
		sectionLocation += sectionSize;
	}
	
	IMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;

	dosHeader = (PIMAGE_DOS_HEADER)hInstance;//cast hInstance to (IMAGE_DOS_HEADER *) - the MZ Header
	ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);//The PE Header begin after the MZ Header (which has size of e_lfanew)
	optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader); //Getting OptionalHeader
	dataDirectory = (IMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory[IMPORT_TABLE_OFFSET]);//Getting the import table of DataDirectory
	
	saveFile.close();
	return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hInstance + dataDirectory.VirtualAddress);//ImageBase+RVA to import table

}
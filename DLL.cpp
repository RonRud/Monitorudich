#include "DLL.h"
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH: {
		std::cout << "Got to dll main" << std::endl;
		//Get info from the main program via info_to_dll.txt file
		std::string dllRecievedInfo;
		std::ifstream myfile("C:\\Windows\\Temp\\info_to_dll.txt");
		int attamptToHookNumFunctions;
		if (myfile.is_open())
		{
			if (std::getline(myfile, dllRecievedInfo))
			{
				strcpy(loggerFilePath, dllRecievedInfo.c_str());
				std::getline(myfile, dllRecievedInfo);
				strcpy(infoFromMainFilePath, dllRecievedInfo.c_str());
				std::getline(myfile, dllRecievedInfo);
				strcpy(infoToMainFilePath, dllRecievedInfo.c_str());
				std::getline(myfile, dllRecievedInfo);
				strcpy(offlineScrapesFile, dllRecievedInfo.c_str());
				std::getline(myfile, dllRecievedInfo);
				strcpy(blacklistFilePath, dllRecievedInfo.c_str());
				std::getline(myfile, dllRecievedInfo);
				strcpy(webScrapperPythonFilePath, dllRecievedInfo.c_str());
				std::getline(myfile, dllRecievedInfo);
				strcpy(executablePath, dllRecievedInfo.c_str());
				std::getline(myfile, dllRecievedInfo);
				isWebScrapingEnabled = std::strtoul(dllRecievedInfo.c_str(), NULL, 10); // read from the eighth line the boolean of isWebScrapingEnabled
				std::getline(myfile, dllRecievedInfo);
				attamptToHookNumFunctions = std::strtoul(dllRecievedInfo.c_str(), NULL, 10);// read from the nineth line the number of functions to hook
			}
			else {
				std::cout << "Unable to read text from info_to_dll.txt, quitting injected dll..." << std::endl;
				myfile.close();
				break;
			}
		}
		else { std::cout << "Unable to open info_to_dll.txt, quitting injected dll..." << std::endl; break; } //be wary that this prints in the inspected child program

		//initialize an empty file
		std::ofstream saveFile(loggerFilePath, std::ios::out | std::ios::trunc);
		saveFile.close();
		std::ofstream infoFromDllToMain(infoToMainFilePath, std::ios::out | std::ios::trunc);
		infoFromDllToMain.close();

		//Save hook functions locations so they can be avoided when logging function calls
		DWORD myFunctionsAddresses[] = { (DWORD)Hook,(DWORD)avoidFunctionLogsCreatedByTheHook,(DWORD)avoidFunctionLogsCreatedByTheHook,(DWORD)logHookName,
								(DWORD)logAdditionalVariables,(DWORD)getStack,(DWORD)logStack,(DWORD)accountForTrampolineHookInOriginFuncAddr };
		for (DWORD functionAddr : myFunctionsAddresses) {
			DWORD functionPtr = functionAddr;
			while (*(byte*)functionPtr != 0xCC) {
				functionPtr++; //get pointer to the end of the function
			}
			myFunctionsStartAndEndAddressesVector.push_back(std::pair<DWORD, DWORD>({ functionAddr,functionPtr }));
			//std::cout << "hook function adddress: " << std::hex << functionAddr << std::endl;
			//std::cout << "end of hook function adddress: " << std::hex << functionPtr << std::endl;
		}

		std::cout << loggerFilePath << std::endl;
		std::cout << infoToMainFilePath << std::endl;
		std::cout << infoFromMainFilePath << std::endl;
		std::cout << offlineScrapesFile << std::endl;
		std::cout << blacklistFilePath << std::endl;
		std::cout << webScrapperPythonFilePath << std::endl;
		std::cout << executablePath << std::endl;

		IAThooking(GetModuleHandleA(NULL), attamptToHookNumFunctions);

		//change the process to it's original working directory (where the executable is)
		if (SetCurrentDirectory(executablePath) == 0) {
			std::cout << "Failed to change working directory" << std::endl;
			std::cout << GetLastError() << std::endl;
		};

		std::cout << "dllmain finished executing" << std::endl << std::endl << std::endl;
		//resume main program by indicating it can continue to run
		std::ofstream sendToMainFile(infoToMainFilePath, std::ios::out | std::ios::app);
		sendToMainFile << std::endl << "Main program can continue executing";
		sendToMainFile.close();
		break;
	}
	case DLL_PROCESS_DETACH:
		IAThookingCleanup();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return true;
}

bool IAThooking(HMODULE hInstance, int attamptToHookNumFunctions)
{
	bool flag = false;

	PIMAGE_IMPORT_DESCRIPTOR importedModule;
	PIMAGE_THUNK_DATA pFirstThunk, pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME pFuncData;

	importedModule = getImportTable(hInstance);
	//pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hInstance, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize); - You can just call this function to get the Import Table

	//log file 
	std::ofstream saveFile(loggerFilePath, std::ios::out | std::ios::app);

	int functionAttamptedToHookCounter = 0;
	std::vector<const char*> blackList;
	std::ifstream blacklistFile(blacklistFilePath);
	if (blacklistFile.is_open()) {
		std::string blacklistedFunctionName;
		while (std::getline(blacklistFile, blacklistedFunctionName)) {
			const char* entry = (new std::string(blacklistedFunctionName))->c_str();
			blackList.push_back(entry);
		}
		blacklistFile.close();
	}
	else {
		std::cout << "can't access Black list file" << std::endl;
	}

	while (*(WORD*)importedModule != 0) //over on the modules (DLLs)
	{
		if (strcmp((char*)((PBYTE)hInstance + importedModule->Name), (char*)"COMCTL32.dll") == 0 || strcmp((char*)((PBYTE)hInstance + importedModule->Name), (char*)"SHELL32.dll") == 0
			|| strcmp((char*)((PBYTE)hInstance + importedModule->Name), (char*)"OLEAUT32.dll") == 0) {
			std::cout << (char*)((PBYTE)hInstance + importedModule->Name) << "skipped" << std::endl;
			importedModule++;
			continue;
		}
		saveFile << std::endl << (char*)((PBYTE)hInstance + importedModule->Name) << ":" << std::endl;//printing Module Name
		pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->FirstThunk);//pointing to its IAT
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->OriginalFirstThunk);//pointing to OriginalThunk
		pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);// and to IMAGE_IMPORT_BY_NAME

		while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0) //moving over IAT and over names' table
		{
			saveFile << "0x" << std::hex << pFirstThunk->u1.Function << "\t\t" << pFuncData->Name << std::endl;//printing function's name and addr
			std::ofstream infoToMainFile(infoToMainFilePath, std::ios::out | std::ios::app);
			infoToMainFile << std::endl << pFuncData->Name;
			infoToMainFile.close();
			/*
			std::vector<const char*> blackList = { "EnterCriticalSection", "LeaveCriticalSection", "HeapFree", "HeapAlloc", //8B = mov function crushes
				"GetLastError", "SetLastError", "WriteFile", "GetProcessHeap", //FF 25 = call function crushes
			//from here these are excludes from runtime problems
			"MultiByteToWideChar","FlushFileBuffers","SetFilePointerEx","CreateFileW","CloseHandle","TryEnterCriticalSection","GetFileType","DecodePointer",
				"WideCharToMultiByte","GetModuleHandleW","EncodePointer","IsProcessorFeaturePresent","RtlUnwind",
				//maybe the GetModuleHandleW is unneccery
			"ReadFile"}; //ReadFile breaks because it is used after hook is web scraper code, needs fixing
			//, "free", "malloc"}; they might be broken still
			*/
			if (attamptToHookNumFunctions <= functionAttamptedToHookCounter) {
				saveFile << "function hooking skipped as part of the dynamic blacklist creation functionality" << std::endl;
				break; // only hook a certain amount of functions, this is used for creating a dynamic blacklist
			}

			bool shouldHook = true;
			for (const char* name : blackList) {
				if (strcmp(name, (char*)pFuncData->Name) == 0) {
					shouldHook = false;
					saveFile << "Blacklisted, not hooked" << std::endl << std::endl;
					break;
				}
			}

			if (shouldHook) {
				bool isHooked = inlineHookFunction(pFirstThunk->u1.Function, new std::string(pFuncData->Name));
				if (isHooked) {
					saveFile << "Hooked function successfully" << std::endl;
				}
				else {
					saveFile << "Didn't Hook function" << std::endl;
				}
				saveFile << std::endl;
			}
			pOriginalFirstThunk++; // next node (function) in the array
			pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);
			pFirstThunk++;// next node (function) in the array
			functionAttamptedToHookCounter++;
		}
		importedModule++; //next module (DLL)
	}
	saveFile.close();
	return false;
}

void inlineHookFunctionCleanup(DWORD functionAddr) {
	if (*(BYTE*)functionAddr == 0xE9) {
		functionAddr += *(int*)(functionAddr + 1) + 5;
		return inlineHookFunctionCleanup(functionAddr);
	}
	/* trampolines are hooked differently now and have a seperated cleanup
	else if (*(BYTE*)functionAddr == 0xFF && *(BYTE*)(functionAddr + 1) == 0x25) {
		DWORD dsOffsetOfFunction = *(DWORD*)(functionAddr + 2);

		__asm {
			push eax
			push ebx
			mov ebx, dsOffsetOfFunction
			mov eax, ds: [ebx]
			mov functionAddr, eax
			pop ebx
			pop eax
		}
		return inlineHookFunctionCleanup(functionAddr);
	}*/
	else {
		DWORD Old;
		DWORD n;
		//got to function and not function call trampolines
		VirtualProtect((void*)functionAddr, 5, PAGE_EXECUTE_READWRITE, &Old);
		//Set back to original opcodes mov edi,edi
		//							   push ebp
		//							   mov ebp,esp
		*(BYTE*)functionAddr = 0x8B;
		*(BYTE*)(functionAddr + 1) = 0xFF;
		*(BYTE*)(functionAddr + 2) = 0x55;
		*(BYTE*)(functionAddr + 3) = 0x8B;
		*(BYTE*)(functionAddr + 4) = 0xEC;
		VirtualProtect((void*)functionAddr, 5, Old, &n);
	}
}

void IAThookingCleanup() {
	// regular inline functions cleanup
	for (auto& iterator : addressToNameMap) {
		inlineHookFunctionCleanup(iterator.first);
		delete iterator.second;
	}
	std::ofstream sendToMainFile(infoToMainFilePath, std::ios::out | std::ios::app);
	// trampoline hook cleanup
	for (auto& iterator : trampolineLocationToFunctionLocationDsOffset) {
		sendToMainFile << std::endl << "cleaning up fanction " << *addressToNameMap[iterator.first] << ", with offset: " << std::hex << trampolineLocationToFunctionLocationDsOffset[iterator.first];
		DWORD Old;
		DWORD n;
		//got to function and not function call trampolines
		VirtualProtect((void*)iterator.first, 6, PAGE_EXECUTE_READWRITE, &Old);
		*(BYTE*)iterator.first = 0xFF;
		*(BYTE*)(iterator.first + 1) = 0x25;
		*(DWORD*)(iterator.first + 2) = iterator.second;
		VirtualProtect((void*)iterator.first, 6, Old, &n);
	}
	sendToMainFile.close();
}


void logHookName() {
	std::ofstream saveFile(loggerFilePath, std::ios::out | std::ios::app);
	saveFile << "name: " << *addressToNameMap[originFuncAddr - 5] << ", "; //gets the function's name from the table. The function address which is gathered from the stack 
																		 //has 5 more so it points to the instruction after the jmp in the function and not the function starting point.
	saveFile << "address: 0x" << std::hex << originFuncAddr - 5 << ", ";
	saveFile.close();

	std::ofstream infoToMainFile(infoToMainFilePath, std::ios::out | std::ios::app); // TODO fix this, this is a shortcut to get the last function called to main program 
																							  // so the main program will know the last function that ran in case it crashes (for blacklist)
	infoToMainFile << std::endl << *addressToNameMap[originFuncAddr - 5];
	infoToMainFile.close();
}

void logAdditionalVariables() {
	DWORD funcAddrPtr = originFuncAddr;
	std::ofstream saveFile(loggerFilePath, std::ios::out | std::ios::app);
	saveFile << "eax: 0x" << std::hex << savedEax << ", ";
	saveFile << "ebx: 0x" << std::hex << savedEbx << ", ";
	saveFile << "ecx: 0x" << std::hex << savedEcx << ", ";
	saveFile << "edx: 0x" << std::hex << savedEdx << ", ";

	foundWINAPICleanup = false;
	while ((*(BYTE*)(funcAddrPtr) != 0xC3 && *(BYTE*)(funcAddrPtr) != 0xCB) && !(*(BYTE*)(funcAddrPtr) == 0xCC && *(BYTE*)(funcAddrPtr + 1) == 0xCC)) { //checks while still in function, stop checking if it reaches opcodes
																																					//that indicate that the function is not in the WINAPI format or if it reaches CC CC
		//if (*(BYTE*)(funcAddrPtr) == 0xCC && *(BYTE*)(funcAddrPtr + 1) == 0xCC) {
		//	break;
		//}
		if (*(BYTE*)(funcAddrPtr) == 0xC2) { //get number of bytes from the corresponding ret opcodes acccording to the WINAPI function call //&& *(BYTE*)(funcAddrPtr+2)==0x00) { add this if the parameters of winapi bug
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
		if (functionParamsNum > MAX_STACK_TO_SHOW) {
			functionParamsNum = MAX_STACK_TO_SHOW; //Max of MAX_STACK_TO_SHOW hex so it doesn't save a ton of memory and looks bad
		}
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

std::string utf8_encode(const std::wstring& wstr)
{
	if (wstr.empty()) return std::string();
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
}

void logStack() {
	std::ofstream saveFile(loggerFilePath, std::ios::out | std::ios::app);
	saveFile << "presumed function bytes in hex: ";
	for (int i = 0; i < functionParamsNum; i++) {
		saveFile << std::hex << functionParameters[i] << "-";
	}
	saveFile << ", ";
	saveFile.flush();
	if (isWebScrapingEnabled) {
		std::string functionDocStr = *nameToDocumantationString[addressToNameMap[originFuncAddr - 5]];
		size_t index = functionDocStr.find('(');
		saveFile << "presumed function parameters: ";
		for (int i = 0; i < functionParamsNum; i++) {
			size_t firstSpace = functionDocStr.find(' ', index); // between the first and second space is the data type
			size_t secondSpace = functionDocStr.find(' ', firstSpace + 1); // after the second space space is the documantation name for the variable
			if (firstSpace == std::string::npos || secondSpace == std::string::npos) { break; }
			std::string parameterType = functionDocStr.substr(firstSpace + 1, secondSpace - firstSpace - 1);
			
			saveFile << parameterType << "=";
			size_t nextSpace = functionDocStr.find(' ', secondSpace+1); //this finds the next space which will be after the , or before the closing ), this is an ugly solution

			__try {
				//std::cout << *addressToNameMap[originFuncAddr - 5] << " : " << functionDocStr.substr(secondSpace + 1, nextSpace - secondSpace - 2) << std::endl;
				//Desicion tree on how to treat data types
				if (functionDocStr.substr(secondSpace + 1, nextSpace - secondSpace - 2) == "lpBuffer") {
					saveFile << "~wstr " << "\"" << utf8_encode((LPCWSTR)functionParameters[i]) << "\"";
				}
				else if (parameterType == "LPARAM" || parameterType == "long") {
					saveFile << "long" << (LPARAM)functionParameters[i]; //basically long
				}
				else if (parameterType == "LPBOOL") {
					saveFile << "boolean " << *(LPBOOL)functionParameters[i];
				}
				else if (parameterType == "LPCCH") {
					saveFile << "char " << *(LPCCH)functionParameters[i];
				}
				else if (parameterType == "LPCSTR") {
					saveFile << "\"" << (LPCSTR)functionParameters[i] << "\"";
				}
				else if (parameterType == "LPCTSTR") {
					saveFile << "\"" << (LPCTSTR)functionParameters[i] << "\"";
				}
				else if (parameterType == "LPCWSTR") {
					saveFile << "\"" << utf8_encode((LPCWSTR)functionParameters[i]) << "\"";
				}
				else if (parameterType == "LPWSTR") {
					saveFile << "\"" << utf8_encode((LPWSTR)functionParameters[i]) << "\"";
				}
				else if (parameterType == "LPSTR") {
					saveFile << "\"" << (LPSTR)functionParameters[i] << "\"";
				}
				else if (parameterType == "LPWORD") {
					saveFile << "WORD " << *(LPWORD)functionParameters[i];
				}
				else if (parameterType == "WPARAM" || parameterType == "UINT") {
					saveFile << "UINT " << (UINT)functionParameters[i];
				}
				//else if (parameterType == "VOID*" || parameterType == "LPVOID") {
				//	saveFile << "VOID*~wstr attempt " << "\"" << utf8_encode((LPCWSTR)functionParameters[i]) << "\"";
				//}
				else if (parameterType == "int") {
					saveFile << "int " << (int)functionParameters[i];
				}
				else {
					//just display hex
					saveFile << "0x" << functionParameters[i];
				}
				saveFile << ",";

				if (functionDocStr.find(',', index) == std::string::npos || functionDocStr.find(',', index) >= functionDocStr.find(';')) { break; } //lazy if
			}
			__except (0) {}
			index = functionDocStr.find(',', index + 1);

		}
	}
	else { saveFile << ", "; }
	saveFile << std::endl;
	saveFile.close();
}

/* This function was created to decide whether to return "normally" to where the function was called
* aka the location pushed onto the stack by the call instruction.
* or return to the actual function and not where the function was called because the hook was on a trampoline
* and the execution of code needs to continue from the actual function and not the assembly after the trampoline jmp
*/
void accountForTrampolineHookInOriginFuncAddr() {
	auto actualFunctionAddr = trampolineLocationToFunctionLocation.find(originFuncAddr-5);
	if (actualFunctionAddr == trampolineLocationToFunctionLocation.end()) {
		//the function was not called from a trampoline hook so do nothing
	}
	else {
		originFuncAddr = actualFunctionAddr->second;
		// if we hook the trampoline we don't want to do the stack setup as it wasn't replaced and will still happen (doesn't have to be the winapi setup)
		// therefore we will return from this function
		__asm {
			//compiler did shit so this is the reversing of it
			pop ebx
			mov esp,ebp
			pop ebp

			pop eax // first we will get rid of the return address to the inline hook
			PUSH originFuncAddr

			mov eax, savedEax
			mov ebx, savedEbx
			mov ecx, savedEcx
			mov edx, savedEdx
			
			retn
		}
	}
}

void avoidFunctionLogsCreatedByTheHook() {
	//Check if the function call originated from the hook and if so stop the hook from logging the function (return)
	for (std::pair<DWORD, DWORD> functionsStartAndEndAddressPair : myFunctionsStartAndEndAddressesVector) {
		if (functionsStartAndEndAddressPair.first <= originFuncAddr && originFuncAddr <= functionsStartAndEndAddressPair.second) {
			//the function was called from the hook and not the user program, therefore let's finish the hook without logging anything
			//this will also not call any other API calls therefore preventing functions creating stack overflow
			accountForTrampolineHookInOriginFuncAddr();

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
	}
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
	avoidFunctionLogsCreatedByTheHook();
	logHookName();
	logAdditionalVariables();
	getStack();
	logStack();
	accountForTrampolineHookInOriginFuncAddr();

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


std::string replaceSubstrInString(std::string str, std::string replaceStr, std::string toStr) {
	size_t index = 0;
	while (true) {
		/* Locate the substring to replace. */
		index = str.find(replaceStr, index);
		if (index == std::string::npos) break;

		/* Make the replacement. */
		str.replace(index, toStr.length(), toStr);

		/* Advance index forward so the next iteration doesn't pick it up as well. */
		index += toStr.length();
	}
	return str;
}

void webScrapeFunction(std::string* functionName) {
	std::cout << "web scraping function: " << *functionName << std::endl;
	std::string line;
	bool foundOfflineScrape = false;
	std::ifstream myfile(offlineScrapesFile);
	if (myfile.is_open())
	{
		while (std::getline(myfile, line))
		{
			const size_t seperatorIdx = line.rfind('-');
			if (line.substr(0, seperatorIdx) == (*functionName)) {
				foundOfflineScrape = true;
				nameToDocumantationString[functionName] = new std::string(line.substr(seperatorIdx + 1, line.length() - seperatorIdx - 1)); //get only the scraped string (after the -)
			}
		}
		myfile.close();
	}
	else { std::cout << "Unable to open " << offlineScrapesFile << ", can't use offline scrape data" << std::endl; } //be wary that this prints in the inspected child program
	if (foundOfflineScrape == false) {
		//run and get data as string from python web scrape
		HANDLE hStdOutPipeRead = NULL;
		HANDLE hStdOutPipeWrite = NULL;

		// Create two pipes.
		SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
		if (CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0) == false) {
			throw std::runtime_error("couldn't create output pipe for web scrape");
		}
		// Create the process.
		STARTUPINFO si = { };
		si.cb = sizeof(STARTUPINFO);
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdError = hStdOutPipeWrite;
		si.hStdOutput = hStdOutPipeWrite;
		PROCESS_INFORMATION pi = { };
		LPCWSTR lpApplicationName = L"C:\\Windows\\System32\\cmd.exe";
		std::string stringCommandLine = "python " + std::string(webScrapperPythonFilePath) + " " + (*functionName);
		std::wstring* windwosStringShit = new std::wstring(stringCommandLine.begin(), stringCommandLine.end());
		const wchar_t* commandLineWchars = (*windwosStringShit).c_str();
		LPWSTR lpCommandLine = const_cast<LPWSTR>(commandLineWchars);
		LPSECURITY_ATTRIBUTES lpProcessAttributes = NULL;
		LPSECURITY_ATTRIBUTES lpThreadAttribute = NULL;
		BOOL bInheritHandles = TRUE;
		DWORD dwCreationFlags = 0;
		LPVOID lpEnvironment = NULL;
		LPCWSTR lpCurrentDirectory = NULL;
		if (!CreateProcessW(
			NULL,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttribute,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			LPSTARTUPINFOW(&si),
			&pi)) {
			throw std::runtime_error("couldn't create child process for web scrape");
		}
		WaitForSingleObject(pi.hProcess, INFINITE); //wait for process to finish

		// Close pipes we do not need.
		CloseHandle(hStdOutPipeWrite);

		// The main loop for reading output from the DIR command.
		char buffer[1024 + 1] = { };
		DWORD dwRead = 0;
		DWORD dwAvail = 0;

		std::ofstream saveFile(offlineScrapesFile, std::ios::out | std::ios::app);
		while (ReadFile(hStdOutPipeRead, buffer, 1024, &dwRead, NULL))
		{
			std::string* modifiedBuffer = new std::string("");
			//buffer[dwRead] = '\0';
			for (int i = 0; i < dwRead + 1; i++) {
				if (buffer[i] == ')') {
					modifiedBuffer->push_back(' ');
					modifiedBuffer->push_back(')');
					modifiedBuffer->push_back(';');
					break;
				}
				else if (buffer[i] == '\t' && buffer[i + 1] == '\t') {
					if (buffer[i + 1] != ' ' && buffer[i + 1] != ' ' && buffer[i - 1] != ' ') { //prevent double weird spaces
						modifiedBuffer->push_back(' ');
					}
					i++;
				}
				else if (buffer[i] == '\t' || buffer[i] == ' ') { // wtf windows why is there a non space space (hover to see shenaniganery)
					if (buffer[i + 1] != ' ' && buffer[i + 1] != ' ' && buffer[i-1] != ' ') { //prevent double weird spaces
						modifiedBuffer->push_back(' ');
					}
				}
				else if (buffer[i] == ' ' && buffer[i + 1] == '*') { //saves void *name to void* name for better scraping
					modifiedBuffer->push_back('*');
					modifiedBuffer->push_back(' ');
					i++; //skip writing the * again
				}
				else if (buffer[i] != '\r' && buffer[i] != '\n' && !(buffer[i] == ' ' && buffer[i + 1] == ' ')) {
					modifiedBuffer->push_back(buffer[i]);
				}
			}
			while (true) {
				/* Locate the substring to replace. */
				size_t openSquareIndex = modifiedBuffer->find(' [', 0);
				size_t closeSquareIndex = modifiedBuffer->find(']', 0);
				if (openSquareIndex == std::string::npos) break;
				if (closeSquareIndex == std::string::npos) break;
				modifiedBuffer->erase(openSquareIndex,closeSquareIndex-openSquareIndex+2);
			}
			while (true) {
				/* Locate the substring to replace. */
				size_t openIndex = modifiedBuffer->find(" _", 0);
				size_t closeIndex = modifiedBuffer->find("_ ", openIndex);
				if (openIndex == std::string::npos) break;
				if (closeIndex == std::string::npos) break;
				modifiedBuffer->erase(openIndex, closeIndex-openIndex+1);
			}
			std::cout << *modifiedBuffer << std::endl;
			nameToDocumantationString[functionName] = modifiedBuffer;
			//save string to the offlineScrapesFile
			saveFile << *functionName << "-" << *nameToDocumantationString[functionName] << std::endl;
		}
		// Clean up and exit.
		CloseHandle(hStdOutPipeRead);

		//TODO Start of DLL connection to web scaper, need python scraper and usage in runtime function call
	}
}


bool inlineHookFunction(DWORD functionAddr, std::string* functionName)
{
	std::ofstream saveFile(loggerFilePath, std::ios::out | std::ios::app);

	DWORD Old;
	DWORD n;
	DWORD numBytes = 5;
	saveFile << "function addr: " << std::hex << functionAddr << std::endl;
	saveFile << "The first bytes of the function are: ";
	char buffer[100];
	sprintf(buffer, "%02X %02X %02X %02X %02X %02X", *(BYTE*)functionAddr, *(BYTE*)(functionAddr + 1), *(BYTE*)(functionAddr + 2), *(BYTE*)(functionAddr + 3), *(BYTE*)(functionAddr + 4), *(BYTE*)(functionAddr + 5));
	saveFile << buffer << std::endl;
	if (*(BYTE*)functionAddr == 0x8B && *(BYTE*)(functionAddr + 1) == 0xFF) {
		//If the code gets here the function is valid to hook
		//TODO here there will be the call to web scraping if enabled
		if (isWebScrapingEnabled) {
			webScrapeFunction(functionName);
		}
		//Hook the function
		addressToNameMap[functionAddr] = functionName;
		VirtualProtect((void*)functionAddr, 5, PAGE_EXECUTE_READWRITE, &Old);
		*(BYTE*)functionAddr = 0xE8; //call Opcode
		*(DWORD*)(functionAddr + 1) = (DWORD)Hook - (DWORD)functionAddr - 5; //Calculate amount of bytes to jmp
		VirtualProtect((void*)functionAddr, 5, Old, &n);
		//That's it...hooked.
		//it only required a bit of satanic worship, only a couple things were sacrificed
		saveFile.close();
		return true;

	}
	else if (*(BYTE*)functionAddr == 0xE9) {
		functionAddr += *(int*)(functionAddr + 1) + 5;
		return inlineHookFunction(functionAddr, functionName);
	}
	else if (*(BYTE*)functionAddr == 0xFF && *(BYTE*)(functionAddr + 1) == 0x25) {
		DWORD dsOffsetOfFunction = *(DWORD*)(functionAddr + 2);
		DWORD trampolineLocation = functionAddr;
		addressToNameMap[trampolineLocation] = functionName; //save the calling address to the hook (in this case it will be called from the trampoline location)
		
		//Hook the trampoline
		VirtualProtect((void*)trampolineLocation, 6, PAGE_EXECUTE_READWRITE, &Old);
		*(BYTE*)trampolineLocation = 0xE8; //call Opcode
		*(DWORD*)(trampolineLocation + 1) = (DWORD)Hook - (DWORD)trampolineLocation - 5; //Calculate amount of bytes to jmp
		*(BYTE*)(trampolineLocation + 5) = 0xAA; //change the last byte to unique identifier (shouldn't really matter because it will never execute anyway)
		VirtualProtect((void*)trampolineLocation, 6, Old, &n);


		__asm {
			push eax
			push ebx
			mov ebx, dsOffsetOfFunction
			mov eax, ds: [ebx]
			mov functionAddr, eax
			pop ebx
			pop eax
		}
		trampolineLocationToFunctionLocation[trampolineLocation] = functionAddr;
		trampolineLocationToFunctionLocationDsOffset[trampolineLocation] = dsOffsetOfFunction;// save the offset value for the hook cleanup 

		//std::cout << "Trampoline hooking function: " << *functionName << ", log continue in address: " << std::hex << dsOffsetOfFunction << std::endl;
		if (isWebScrapingEnabled) {
			webScrapeFunction(functionName);
		}
		saveFile.close();
		// TODO need to add cleanup
		return true;
	}
	else {
		saveFile.close();
		return false;
	}
}


PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hInstance)
{
	std::map<int, char*> subsystemsDict{ {0,"IMAGE_SUBSYSTEM_UNKNOWN"}, {1,"IMAGE_SUBSYSTEM_NATIVE"}, {2,"IMAGE_SUBSYSTEM_WINDOWS_GUI"}, {3,"IMAGE_SUBSYSTEM_WINDOWS_CUI"},
		{5,"IMAGE_SUBSYSTEM_OS2_CUI"}, {7,"IMAGE_SUBSYSTEM_POSIX_CUI"}, {9,"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"}, {10,"IMAGE_SUBSYSTEM_EFI_APPLICATION"}, {11,"IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"},
		{12,"IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"}, {13,"IMAGE_SUBSYSTEM_EFI_ROM"}, {14,"IMAGE_SUBSYSTEM_XBOX"}, {16,"IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"} };
	//std::cout << "IN PE Logger" << std::endl;
	std::ofstream saveFile(loggerFilePath, std::ios::out | std::ios::app);
	saveFile << "PE header extraction" << std::endl << std::endl;
	// IMAGE_DOS_HEADER
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hInstance;
	saveFile << "--DOS HEADER--" << std::endl;
	if (dosHeader->e_magic != 0x5a4d) { //check if MZ (signature of DOS)
		throw std::invalid_argument("received non DOS file");
	}
	saveFile << "\t0x" << std::hex << dosHeader->e_magic << "\t\tMagic number" << std::endl;
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
	saveFile << "\t" << std::hex << imageNTHeaders->Signature << "\t\tSignature" << std::endl;

	// FILE_HEADER
	saveFile << "--FILE HEADER--" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->FileHeader.Machine << "\t\tMachine" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->FileHeader.NumberOfSections << "\t\tNumber of Sections" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->FileHeader.TimeDateStamp << "\tTime Stamp" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->FileHeader.PointerToSymbolTable << "\t\tPointer to Symbol Table" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->FileHeader.NumberOfSymbols << "\t\tNumber of Symbols" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->FileHeader.SizeOfOptionalHeader << "\t\tSize of Optional Header" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->FileHeader.Characteristics << "\t\tCharacteristics" << std::endl;
	saveFile.flush();

	// OPTIONAL_HEADER
	saveFile << "--OPTIONAL HEADER--" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.Magic << "\t\tMagic" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MajorLinkerVersion << "\t\tMajor Linker Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MinorLinkerVersion << "\t\tMinor Linker Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfCode << "\t\tSize Of Code" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfInitializedData << "\t\tSize Of Initialized Data" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfUninitializedData << "\t\tSize Of UnInitialized Data" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.AddressOfEntryPoint << "\t\tAddress Of Entry Point (.text)" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.BaseOfCode << "\t\tBase Of Code" << std::endl;
	//saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.BaseOfData << "\t\tBase Of Data" << std::endl; not sure why this was commented out
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.ImageBase << "\t\tImage Base" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SectionAlignment << "\t\tSection Alignment" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.FileAlignment << "\t\tFile Alignment" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion << "\t\tMajor Operating System Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion << "\t\tMinor Operating System Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MajorImageVersion << "\t\tMajor Image Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MinorImageVersion << "\t\tMinor Image Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MajorSubsystemVersion << "\t\tMajor Subsystem Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.MinorSubsystemVersion << "\t\tMinor Subsystem Version" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.Win32VersionValue << "\t\tWin32 Version Value" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfImage << "\t\tSize Of Image" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfHeaders << "\t\tSize Of Headers" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.CheckSum << "\t\tCheckSum" << std::endl;
	if (subsystemsDict.find(imageNTHeaders->OptionalHeader.Subsystem) != subsystemsDict.end()) { //this means it found the subsystem therefore adding translation (cui/gui/...)
		saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.Subsystem << " (speculated): " << subsystemsDict[imageNTHeaders->OptionalHeader.Subsystem] << "\t\tSubsystem" << std::endl;
	}
	else {
		saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.Subsystem << "\t\tSubsystem" << std::endl;
	}
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.DllCharacteristics << "\t\tDllCharacteristics" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfStackReserve << "\t\tSize Of Stack Reserve" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfStackCommit << "\t\tSize Of Stack Commit" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfHeapReserve << "\t\tSize Of Heap Reserve" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfHeapCommit << "\t\tSize Of Heap Commit" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.LoaderFlags << "\t\tLoader Flags" << std::endl;
	saveFile << "\t0x" << std::hex << imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes << "\t\tNumber Of Rva And Sizes" << std::endl;
	saveFile.flush();

	// DATA_DIRECTORIES
	saveFile << "--DATA DIRECTORIES--" << std::endl;
	saveFile << "\tExport Directory Address: 0x" << std::hex << imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress << "; Size: 0x" << std::hex << imageNTHeaders->OptionalHeader.DataDirectory[0].Size << std::endl;
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
		saveFile << "\t\t0x" << std::hex << sectionHeader->Misc.VirtualSize << "\t\tVirtual Size" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->VirtualAddress << "\t\tVirtual Address" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->SizeOfRawData << "\t\tSize Of Raw Data" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->PointerToRawData << "\t\tPointer To Raw Data" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->PointerToRelocations << "\t\tPointer To Relocations" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->PointerToLinenumbers << "\t\tPointer To Line Numbers" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->NumberOfRelocations << "\t\tNumber Of Relocations" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->NumberOfLinenumbers << "\t\tNumber Of Line Numbers" << std::endl;
		saveFile << "\t\t0x" << std::hex << sectionHeader->Characteristics << "\tCharacteristics" << std::endl;

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
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
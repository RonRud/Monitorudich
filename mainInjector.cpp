#include <Windows.h>
#include <iostream>
#include <string>

#include <map>
#include <fstream>
#include <vector>

#pragma comment(lib,"pdh.lib")
#include <Pdh.h>

bool InjectDLL(DWORD ProcessID)
{

	char thisFilePath[100] = { 0 };

	GetModuleFileName(NULL, thisFilePath, 100);
	std::string DllPath = std::string(thisFilePath);
	const size_t last_slash_idx = DllPath.rfind('\\'); //Get the last occurareance of \\ (before the exe name)
	if (std::string::npos != last_slash_idx) {
		DllPath = DllPath.substr(0, last_slash_idx + 1) + "DLL.dll"; // Than add the dll file name to it
	};

	//Send required info to dll
	std::string loggerFilePath = std::string(thisFilePath);
	const size_t last_slash_idx_logger = loggerFilePath.rfind('\\'); //Get the last occurareance of \\ (before the exe name)
	if (std::string::npos != last_slash_idx_logger) {
		loggerFilePath = loggerFilePath.substr(0, last_slash_idx_logger + 1) + "logger_output.txt"; // Than add the logger file name to it
	};
	std::string pathOfFileToDll = loggerFilePath.substr(0, last_slash_idx_logger + 1) + "info_to_dll.txt";
	std::string pathOfFileFromDll = loggerFilePath.substr(0, last_slash_idx_logger + 1) + "dll_to_main_program.txt";
	std::string pathOfOfflineScrapes = loggerFilePath.substr(0, last_slash_idx_logger + 1) + "MSDNScrapes.txt";
	std::string pathOfBlacklist = loggerFilePath.substr(0, last_slash_idx_logger + 1) + "Natural_selector.txt";
	std::string pathOfWebScrapper = loggerFilePath.substr(0, last_slash_idx_logger + 1) + "webScrapperMSDN.py";
	std::string pathOfWebScrapper = "This isn't needed when injecting, let it fail";

	bool blacklistIterate = true;
	bool isWebScrapingEnabled = true;
	int numberOfFunctionsToPossiblyHook = 55555;

	//Send data to injected dll
	std::ofstream dllInfoFile("C:\\Windows\\Temp\\info_to_dll.txt", std::ios::out | std::ios::trunc);
	dllInfoFile << loggerFilePath << std::endl;
	dllInfoFile << pathOfFileToDll << std::endl;
	dllInfoFile << pathOfFileFromDll << std::endl;
	dllInfoFile << pathOfOfflineScrapes << std::endl;
	dllInfoFile << pathOfBlacklist << std::endl;
	dllInfoFile << pathOfWebScrapper << std::endl;
	dllInfoFile << pathOfExecutable << std::endl;
	dllInfoFile << isWebScrapingEnabled << std::endl;
	dllInfoFile << numberOfFunctionsToPossiblyHook << std::endl;
	dllInfoFile.close();
	//clean the recieving file
	std::ofstream mainInfoFileFromDll("dll_to_main_program.txt", std::ios::out | std::ios::trunc);



	//Get the current memory location of LoadLibraryA function in the current loaded instance of kernel32.dll
	LPVOID llAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (!llAddress) { // if GetProcAddress fails than it will return null and go in this error
		std::cout << "Error: cant get procAddress, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	//Get access to the process that the program desires to hook
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	if (!hProcess) {
		std::cout << "Error: cant open Process!, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	//Save the full path of the injected dll in the inspected process (needs to be in it's address space in order to be called by a thread in the other process)
	LPVOID lpDllAddress = VirtualAllocEx(hProcess, NULL, strlen(DllPath.c_str()) + 1, MEM_COMMIT, PAGE_READWRITE);
	DWORD nBytesWritten;

	if (WriteProcessMemory(hProcess, lpDllAddress, DllPath.c_str(), strlen(DllPath.c_str()) + 1, &nBytesWritten) == 0 || nBytesWritten == 0) //if WriteProcessMemory fails the return value is zero
	{
		std::cout << "Error: WriteProcessMemory failed!, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	//Create the thread that runs the injected dll
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)llAddress, lpDllAddress, NULL, NULL);
	if (!hThread) {
		std::cout << "Error: CreateRemoteThread failed!, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	else { //it succeeded!
		CloseHandle(hThread);
	}
	
	std::cout << "Successful dll injection" << std::endl;
	return true;
}

int main(int argc, char* argv[])
{
	DWORD ProcessID;
	std::string processName;
	while (1)
	{
		std::cout << "Enter Process ID:" << std::endl;
		std::cin >> ProcessID;
		//std::cout << "Enter Executable Name: " << std::endl;
		//std::cin >> processName;
		
		bool is_successful = InjectDLL(ProcessID);
		if (is_successful == false) {
			std::cout << "DLL injection failed" << std::endl;
		}
		/*
		std::ofstream saveFile("process_resources_logger.txt", std::ios::out | std::ios::trunc);

		HQUERY query;
		PDH_STATUS status = PdhOpenQuery(NULL, NULL, &query);

		if (status != ERROR_SUCCESS) {

			std::cout << "Open Query Error" << std::endl;
		}
		std::vector<std::string> performanceCounterNamesVector{ "% Privileged Time","% Processor Time","% User time","Creating Process ID","Elapsed Time","Handle Count","ID Process","IO Data Bytes/sec"
																,"IO Data Operations/sec","IO Other Bytes/sec","IO Read Bytes/sec","IO Write Operations/sec","Page Faults/sec"
																,"Page File Bytes","Page File Bytes Peak","Pool Nonpaged Bytes","Priority Base","Private Bytes","Private Bytes"
																,"Thread Count","Virtual Bytes","Virtual Bytes Peak","Working Set","Working Set - Private","Working Set Peak" };
		std::map<std::string, HCOUNTER> performanceCounterNamesToHandle;

		std::vector<const wchar_t*> cleanupVector;
		for (std::string counterName : performanceCounterNamesVector) {
			std::string wha = "\\Process(" + processName + ")\\" + counterName;
			std::wstring* wha2 = new std::wstring(wha.begin(), wha.end());
			const wchar_t* counterPath = (*wha2).c_str();
			cleanupVector.push_back(counterPath);

			status = PdhAddCounterW(query, LPWSTR(counterPath), NULL, &performanceCounterNamesToHandle[counterName]);
			if (status != ERROR_SUCCESS) {
				std::cout << "Add Counter " << counterName << " Error, status: " << std::hex << status << std::endl;
			}
		}
		PdhCollectQueryData(query);
		while (1) {
			PdhCollectQueryData(query);

			PDH_FMT_COUNTERVALUE pdhValue;
			DWORD dwValue;
			for (auto& iterator : performanceCounterNamesToHandle) {
				status = PdhGetFormattedCounterValue(iterator.second, PDH_FMT_DOUBLE, &dwValue, &pdhValue);
				if (status != ERROR_SUCCESS) {
					std::cout << "Value Error in counter " << iterator.first << " ,status: " << status << std::endl;
				}
				saveFile << iterator.first << ": " << pdhValue.doubleValue << std::endl;
			}
			saveFile << std::endl;
			saveFile.flush();
			Sleep(1000);
		}
		// TODO clean the WSTRING!!!
		for (const wchar_t* windowsStringShit : cleanupVector) {
			delete windowsStringShit;
		}
		PdhCloseQuery(query);
		saveFile.close();
		*/
	}
	return 0;
}

/*
* #define MSGRET(str, ret) { cout << "ERROR: " << str << endl; system("pause"); return ret; }
DWORD procNameToPID(const char *procName)
{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
				MSGRET("Unable to create snapshot.", 0)

		PROCESSENTRY32 process;
		process.dwSize = sizeof(PROCESSENTRY32);

		Process32First(snapshot, &process);
		do
		{
				if (strstr(process.szExeFile, procName))
						return process.th32ProcessID;
		}
		while (Process32Next(snapshot, &process));

		return 0;
}*/
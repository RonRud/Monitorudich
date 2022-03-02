#include <Windows.h>
#include <iostream>
#include <string>
#include <thread>

#include <map>
#include <fstream>
#include <vector>
#include <algorithm>

#pragma comment(lib,"pdh.lib")
#include <Pdh.h>
#include <excpt.h>
#include <stdio.h>

bool keepLoggingSystemResources;

bool InjectDLL(DWORD ProcessID)
{

	char thisFilePath[100] = { 0 };

	GetModuleFileName(NULL, thisFilePath, 100);
	std::string DllPath = std::string(thisFilePath);
	const size_t last_slash_idx = DllPath.rfind('\\'); //Get the last occurareance of \\ (before the exe name)
	if (std::string::npos != last_slash_idx) {
		DllPath = DllPath.substr(0, last_slash_idx + 1) + "DLL.dll"; // Than add the dll file name to it
	};


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

void LogSystemResourcesForProcess(std::string processName) {
	try {
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
		while (keepLoggingSystemResources) {
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
		//clean the WSTRINGS
		for (const wchar_t* windowsStringShit : cleanupVector) {
			delete windowsStringShit;
		}
		PdhCloseQuery(query);
		saveFile.close();
	}
	catch (const std::exception& e) { std::cout << e.what() << std::endl; }
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

DWORD getProcessExitCode(HANDLE processHandle) {
	DWORD childProcessExitCode;
	__try {
		if (!GetExitCodeProcess(processHandle, &childProcessExitCode)) {
			std::cout << "GetExitCodeProcess failed" << std::endl;
		}
		else {
			std::cout << "childProcessExitCode: " << childProcessExitCode << std::endl;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		std::cout << "caught exeption in return exit code" << std::endl;
		std::cout << GetExceptionCode();
		std::cout << "last error: " << GetLastError() << std::endl;
	}
	return childProcessExitCode;
}

int main(int argc, char* argv[])
{
	std::string inspectedProcessPath;
	std::cout << "Enter the full path of the executable you wish to inspect: " << std::endl;
	std::cin >> inspectedProcessPath;
	replaceSubstrInString(inspectedProcessPath, "\\\\", "\\");
	replaceSubstrInString(inspectedProcessPath, "\\", "\\\\");
	//opening the executable
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	std::wstring* windwosStringShit = new std::wstring(inspectedProcessPath.begin(), inspectedProcessPath.end());
	const wchar_t* exePathWchars = (*windwosStringShit).c_str();
	LPCWSTR exePath = const_cast<LPCWSTR>(exePathWchars);

	bool blacklistIterate = true;

	if (blacklistIterate == false) { //Run normally, assumes blacklist is precalculated (this is unadvised)

	// Start the child process suspended. 
		if (!CreateProcessW(exePath,   // No module name (use command line)
			NULL,        // 
			NULL,           // Process handle not inheritable
			NULL,           // Thread handle not inheritable
			FALSE,          // Set handle inheritance to FALSE
			CREATE_SUSPENDED | CREATE_NEW_CONSOLE | DEBUG_PROCESS,              // No creation flags
			NULL,           // Use parent's environment block
			NULL,           // Use parent's starting directory 
			LPSTARTUPINFOW(&si),            // Pointer to STARTUPINFO structure
			&pi)           // Pointer to PROCESS_INFORMATION structure
			)
		{
			std::cout << "CreateProcess failed, error: " << GetLastError() << std::endl;
			return 0;
		}
		std::cout << "created process with pid " << pi.dwProcessId << std::endl;

		//Send data to injected dll
		char thisFilePath[100] = { 0 };

		GetModuleFileName(NULL, thisFilePath, 100);
		std::string loggerFilePath = std::string(thisFilePath);
		const size_t last_slash_idx = loggerFilePath.rfind('\\'); //Get the last occurareance of \\ (before the exe name)
		if (std::string::npos != last_slash_idx) {
			loggerFilePath = loggerFilePath.substr(0, last_slash_idx + 1) + "logger_output.txt"; // Than add the logger file name to it
		};

		bool isWebScrapingEnabled = true;
		int numberOfFunctionsToPossiblyHook = 55555;
		std::ofstream dllInfoFile("info_to_dll.txt", std::ios::out | std::ios::trunc);
		dllInfoFile << isWebScrapingEnabled << "," << loggerFilePath;
		dllInfoFile << "," << numberOfFunctionsToPossiblyHook;
		dllInfoFile.close();
		//clean the recieving file
		std::ofstream mainInfoFileFromDll("dll_to_main_program.txt", std::ios::out | std::ios::trunc);
		//now hook the inspected child process
		bool is_successful = InjectDLL(pi.dwProcessId);
		if (is_successful == false) {
			std::cout << "DLL injection failed" << std::endl;
		}
		//freeze this thread until the injected DLL main() finishes running
		while (true) {
			std::string recievedInfo;
			std::ifstream myfile("dll_to_main_program.txt");
			if (myfile.is_open())
			{
				if (std::getline(myfile, recievedInfo))
				{
					if (recievedInfo == "Main program can continue executing") { break; }
				}/*
				else {
					std::cout << "Unable to read text from dll_to_main_program.txt, quitting main program..." << std::endl;
					myfile.close();
					return 0; //exit program
				}*/
				myfile.close();
			}
			else { std::cout << "Unable to open dll_to_main_program, quitting main program..." << std::endl; return 0; }
		}
		//resumes (starts in this case) the child process
		ResumeThread(pi.hThread);
	}
	else {
		/*
		HANDLE hStdOutPipeRead = NULL;
		HANDLE hStdOutPipeWrite = NULL;

		// Create two pipes.
		SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
		if (CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0) == false) {
			throw std::runtime_error("couldn't create output pipe for error catching in main");
		}
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdError = hStdOutPipeWrite;
		si.hStdOutput = hStdOutPipeWrite;
		*/
		if (!CreateProcessW(exePath,   // No module name (use command line)
			NULL,        // 
			NULL,           // Process handle not inheritable
			NULL,           // Thread handle not inheritable
			TRUE,          // Set handle inheritance to FALSE
			CREATE_SUSPENDED | CREATE_NEW_CONSOLE,              // No creation flags
			NULL,           // Use parent's environment block
			NULL,           // Use parent's starting directory 
			LPSTARTUPINFOW(&si),            // Pointer to STARTUPINFO structure
			&pi)           // Pointer to PROCESS_INFORMATION structure
			)
		{
			std::cout << "CreateProcess failed, error: " << GetLastError() << std::endl;
			return 0;
		}
		std::cout << "created process with pid " << pi.dwProcessId << std::endl;

		//Send data to injected dll
		char thisFilePath[100] = { 0 };

		GetModuleFileName(NULL, thisFilePath, 100);
		std::string loggerFilePath = std::string(thisFilePath);
		const size_t last_slash_idx = loggerFilePath.rfind('\\'); //Get the last occurareance of \\ (before the exe name)
		if (std::string::npos != last_slash_idx) {
			loggerFilePath = loggerFilePath.substr(0, last_slash_idx + 1) + "logger_output.txt"; // Than add the logger file name to it
		};

		bool isWebScrapingEnabled = true;
		int numberOfFunctionsToPossiblyHook = 55555;
		std::ofstream dllInfoFile("info_to_dll.txt", std::ios::out | std::ios::trunc);
		dllInfoFile << isWebScrapingEnabled << "," << loggerFilePath;
		dllInfoFile << "," << numberOfFunctionsToPossiblyHook;
		dllInfoFile.close();
		//clean the recieving file
		std::ofstream mainInfoFileFromDll("dll_to_main_program.txt", std::ios::out | std::ios::trunc);
		//now hook the inspected child process
		bool is_successful = InjectDLL(pi.dwProcessId);
		if (is_successful == false) {
			std::cout << "DLL injection failed" << std::endl;
		}

		Sleep(10000);

		//CloseHandle(hStdOutPipeWrite);

		DWORD childProcessExitCode = getProcessExitCode(pi.hProcess);
		if (childProcessExitCode == STILL_ACTIVE) {
			std::cout << "still active" << std::endl;
		}

		std::cout << "0" << std::endl;
		/*
		// The main loop for reading output from the DIR command.
		char buffer[1024 + 1] = { };
		DWORD dwRead = 0;
		DWORD dwAvail = 0;

		while (ReadFile(hStdOutPipeRead, buffer, 1024, &dwRead, NULL))
		{
			std::cout << "Errors recieved in main from injected dll: " << buffer << std::endl;
		}
		// Clean up and exit.
		CloseHandle(hStdOutPipeRead);
		*/

		//freeze this thread until the injected DLL main() finishes running
		while (true) {
			std::string recievedInfo;
			std::ifstream myfile("dll_to_main_program.txt");
			if (myfile.is_open())
			{
				if (std::getline(myfile, recievedInfo))
				{
					if (recievedInfo == "Main program can continue executing") { break; }
				}/*
				else {
					std::cout << "Unable to read text from dll_to_main_program.txt, quitting main program..." << std::endl;
					myfile.close();
					return 0; //exit program
				}*/
				myfile.close();
			}
			else { std::cout << "Unable to open dll_to_main_program, quitting main program..." << std::endl; return 0; }
		}
		//resumes (starts in this case) the child process
		ResumeThread(pi.hThread);
	}


	try {
		//Log processes system resources
		keepLoggingSystemResources = true;
		const size_t last_slash_idx = inspectedProcessPath.rfind('\\');
		//TODO add with threading
		std::thread threadThing(LogSystemResourcesForProcess, inspectedProcessPath.substr(last_slash_idx + 1, inspectedProcessPath.length() - 5 - last_slash_idx)); //makes sure to pass the name without .exe

		// Wait until child process exits.
		std::cout << "before process terminate check" << std::endl;
		WaitForSingleObject(pi.hProcess, INFINITE);
		std::cout << "after process terminate check" << std::endl;
		keepLoggingSystemResources = false;

		// Close process and thread handles. 
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	catch (const std::exception& e) { std::cout << "crushed, error: " << e.what() << std::endl; }
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
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
std::string pathOfLogger;
std::string pathOfFileToDll;
std::string pathOfFileFromDll;
std::string pathOfOfflineScrapes;
std::string pathOfBlacklist;
std::string pathOfWebScrapper;
std::string pathOfExecutable;

bool blacklistIterate = true;
int runProgramForBeforeCheck = 10000; //in miliseconds
bool isWebScrapingEnabled = true;
int numberOfFunctionsToPossiblyHook = 55555;



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
		//else {
		//	std::cout << "childProcessExitCode: " << childProcessExitCode << std::endl;
		//}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		std::cout << "caught exeption in return exit code" << std::endl;
		std::cout << GetExceptionCode();
	}
	return childProcessExitCode;
}

bool spawnProcessByPath(std::string inspectedProcessPath) {
	//opening the executable
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	std::wstring* windwosStringShit = new std::wstring(inspectedProcessPath.begin(), inspectedProcessPath.end());
	const wchar_t* exePathWchars = (*windwosStringShit).c_str();
	LPCWSTR exePath = const_cast<LPCWSTR>(exePathWchars);

	pathOfExecutable = inspectedProcessPath.substr(0, inspectedProcessPath.rfind('\\') + 1);

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
		std::ofstream dllInfoFile("C:\\Windows\\Temp\\info_to_dll.txt", std::ios::out | std::ios::trunc);
		dllInfoFile << pathOfLogger << std::endl;
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
				while (std::getline(myfile, recievedInfo))
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
		bool programSuccesfullyRunsWithHooks = false;
		while (programSuccesfullyRunsWithHooks == false) {
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
			std::ofstream dllInfoFile("C:\\Windows\\Temp\\info_to_dll.txt", std::ios::out | std::ios::trunc);
			dllInfoFile << pathOfLogger << std::endl;
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

			//now hook the inspected child process
			bool is_successful = InjectDLL(pi.dwProcessId);
			if (is_successful == false) {
				std::cout << "DLL injection failed" << std::endl;
			}

			Sleep(5000);

			DWORD childProcessExitCode = getProcessExitCode(pi.hProcess);
			if (childProcessExitCode == STILL_ACTIVE) {
				std::cout << "child process still active after the dll main" << std::endl;
			}
			else if (childProcessExitCode == 0) {
				throw std::runtime_error("ran succesfully, this should never happen"); // should never get here, program main thread didn't run at this point
			}
			else { //This is the crush test for the injected dll loading, therefore the suspected function
				   //is recieved from the hooking code in the dll
				std::cout << "crushed in dll main, crushed with error code: " << childProcessExitCode << std::endl;
				std::string recievedInfo;
				std::ifstream infoFromInjectedDllFile("dll_to_main_program.txt");
				if (infoFromInjectedDllFile.is_open())
				{
					if (std::getline(infoFromInjectedDllFile, recievedInfo)) {

						while (std::getline(infoFromInjectedDllFile, recievedInfo)) {
							//Make sure to continue with the read of the last line
						}
					}
					else {
						std::cout << "Couldn't read from dll_to_main_program, quitting main program..." << std::endl;
						return 0;
					}
					infoFromInjectedDllFile.close();
				}
				else { std::cout << "Unable to open dll_to_main_program, quitting main program..." << std::endl; return 0; }
				std::cout << "Blacklisting Suspected function named: " << recievedInfo << std::endl;
				std::ofstream blacklistFile("Natural_selector.txt", std::ios::out | std::ios::app);
				blacklistFile << recievedInfo << std::endl;
				blacklistFile.close();
				continue;
			}

			//freeze this thread until the injected DLL main() finishes running
			bool dllmainFinished = false;
			while (dllmainFinished == false) {
				std::string recievedInfo;
				std::ifstream myfile("dll_to_main_program.txt");
				if (myfile.is_open())
				{
					while (std::getline(myfile, recievedInfo))
					{
						if (recievedInfo == "Main program can continue executing") {
							dllmainFinished = true;
							break;
						}
						//if (lstrcmp(recievedInfo.c_str(), TEXT("Main program can continue executing"))==0) { break; }
						recievedInfo = "";
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
			Sleep(runProgramForBeforeCheck);
			childProcessExitCode = getProcessExitCode(pi.hProcess);
			if (childProcessExitCode == STILL_ACTIVE) {
				std::cout << "still active after " << runProgramForBeforeCheck / 1000 << " seconds of the program's main" << std::endl;
				programSuccesfullyRunsWithHooks = true;
			}
			else if (childProcessExitCode == 0) {
				std::cout << "child process finished succesfully" << std::endl;
				programSuccesfullyRunsWithHooks = true;
			}
			else {
				std::cout << "crushed while executing the program's main thread, crush with error code: " << childProcessExitCode << std::endl;
				std::string recievedInfo;
				std::ifstream infoFromInjectedDllFile("dll_to_main_program.txt");
				if (infoFromInjectedDllFile.is_open())
				{
					if (std::getline(infoFromInjectedDllFile, recievedInfo)) {
						while (std::getline(infoFromInjectedDllFile, recievedInfo)) {
							//Make sure to continue with the read of the last line
						}
					}
					else {
						std::cout << "Couldn't read from dll_to_main_program, quitting main program..." << std::endl;
						return 0;
					}
					infoFromInjectedDllFile.close();
				}
				else { std::cout << "Unable to open dll_to_main_program, quitting main program..." << std::endl; return 0; }
				std::cout << "Blacklisting Suspected function named: " << recievedInfo << std::endl;
				std::ofstream blacklistFile("Natural_selector.txt", std::ios::out | std::ios::app);
				blacklistFile << recievedInfo << std::endl;
				blacklistFile.close();
			}
		}
	}

	//Log processes system resources
	try {
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
		std::cout << "whee" << std::endl; // TODO check why ended spawn func doesn't execute (when there isn't a return here)
		return true;
	}
	catch (const std::exception& e) { std::cout << "crushed, error: " << e.what() << std::endl; }
	std::cout << "ended spawn func" << std::endl;
	return true;
}

void mainMenu() {
	while (true) {
		std::string chosenOption;
		std::getline(std::cin, chosenOption);
		if (chosenOption == "spawn") { // spawn child program and hook it
			std::string inspectedProcessPath;
			std::cout << "Enter the full path of the executable you wish to inspect including .exe: " << std::endl;
			std::getline(std::cin, inspectedProcessPath);
			replaceSubstrInString(inspectedProcessPath, "\\\\", "\\");
			replaceSubstrInString(inspectedProcessPath, "\\", "\\\\");
			
			bool didItWork = spawnProcessByPath(inspectedProcessPath);
			std::cout << "wha" << std::endl;
		}
		else if (chosenOption == "blacklist" || chosenOption == "b") { //blacklist status and options
			
			std::cout << "Current blacklist status: " << std::endl;
			std::ifstream readBlacklistFile(pathOfBlacklist);
			if (readBlacklistFile) {
				
				// get length of file:
				readBlacklistFile.seekg(0, readBlacklistFile.end);
				int length = readBlacklistFile.tellg();
				readBlacklistFile.seekg(0, readBlacklistFile.beg);

				char* buffer = new char[length];
				// read the entire file as a block into buffer:
				readBlacklistFile.read(buffer, length);
				
				std::string fileContent(buffer);
				std::getline(readBlacklistFile, fileContent, '\0');

				//Here goes the main action loop
				std::cout << fileContent << std::endl;
				std::cout << std::endl << std::endl << "enter blacklist option. options are: quit, add, remove, remove-all, add-dll, remove-dll" << std::endl;
				std::string blacklistOption;

				while (true) {
					std::getline(std::cin, blacklistOption);

					if (blacklistOption.substr(0, 3) == "add") {
						fileContent.append(blacklistOption.substr(4, blacklistOption.length() - 3).append("\n").c_str());
					}
					else if (blacklistOption.substr(0, 5) == "remove") {
						std::string deleteEntry = blacklistOption.substr(4, blacklistOption.length() - 3);
						size_t place = fileContent.find(deleteEntry.c_str());
						if (place != std::string::npos) {
							fileContent.erase(place, deleteEntry.length());
						}
					}
					else if (blacklistOption == "remove-all") {
						fileContent = "";
					}
					else if (blacklistOption == "add-dll") {
						//TODO lower priorety feature
					}
					else if (blacklistOption == "remove-dll") {
						//TODO lower priorety feature
					}
					else if (blacklistOption == "quit" || blacklistOption == "q") {
						std::ofstream saveFile(pathOfBlacklist, std::ios::out | std::ios::trunc);
						saveFile << fileContent;
						saveFile.close();
						break;
					}
					else {
						std::cout << "Invalid blacklist option, options are: quit, add, remove, remove-all, add-dll, remove-dll" << std::endl;
					}
				}

				//cleanup
				readBlacklistFile.close();
				delete[] buffer;
			}
			else { std::cout << "Unable to open blacklist file, quitting blacklist option..." << std::endl; continue; }

			// TODO print the entire blacklist content and than give user option to add/remove/remove all
			// TODO add option to add filter/ entire DLL
		}
		else if (chosenOption == "quit" || chosenOption == "q") { // quit programs
			exit(0);
		}
		else { // Catch incorrect option, regive the user the log
			std::cout << "Unknown option, options are: " << std::endl;
		}
	}
}



int main(int argc, char* argv[])
{
	//Command line interface

	//Get file path of logger_output.txt (with the additional path to where this program runs)
	char thisFilePath[100] = { 0 };

	GetModuleFileName(NULL, thisFilePath, 100);
	pathOfLogger = std::string(thisFilePath);
	const size_t last_slash_idx = pathOfLogger.rfind('\\'); //Get the last occurareance of \\ (before the exe name)
	if (std::string::npos != last_slash_idx) {
		pathOfLogger = pathOfLogger.substr(0, last_slash_idx + 1) + "logger_output.txt"; // Than add the logger file name to it
	};
	pathOfFileToDll = pathOfLogger.substr(0, last_slash_idx + 1) + "info_to_dll.txt";
	pathOfFileFromDll = pathOfLogger.substr(0, last_slash_idx + 1) + "dll_to_main_program.txt";
	pathOfOfflineScrapes = pathOfLogger.substr(0, last_slash_idx + 1) + "MSDNScrapes.txt";
	pathOfBlacklist = pathOfLogger.substr(0, last_slash_idx + 1) + "Natural_selector.txt";
	pathOfWebScrapper = pathOfLogger.substr(0, last_slash_idx + 1) + "webScrapperMSDN.py";

	blacklistIterate = true;
	runProgramForBeforeCheck = 10000; //in miliseconds
	isWebScrapingEnabled = true;
	numberOfFunctionsToPossiblyHook = 55555;

	mainMenu();

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
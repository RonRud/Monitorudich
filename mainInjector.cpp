#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

using namespace std;
#define MSGRET(str, ret) { cout << "ERROR: " << str << endl; system("pause"); return ret; }


//#define DLL_PATH "C:\\uriel\\Programming\\C++\\DLL Injection\\myDLL.dll"

void InjectDLL(DWORD ProcessID,LPCSTR DLL_PATH);

int main(int argc, char *argv[])
{
	char DLL_PATH[50]={0};
	DWORD ProcessID;
	while(1)
	{
		printf("Enter Process ID:\n");
		scanf("%u", &ProcessID);
		printf("Enter DLL path:\n");
		scanf("%s",DLL_PATH);
		InjectDLL(ProcessID,DLL_PATH);
	}
	return 0;
}

void InjectDLL(DWORD ProcessID,LPCSTR DLL_PATH)
{
	LPVOID llAddress;
	HANDLE hProcess;
	if(!(llAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")))
		printf("Error: cant get procAddr %d",GetLastError());
	if(!(hProcess=OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID)))
		printf("Error cant open Process! (%d)",GetLastError());
	LPVOID lpDllAddress = VirtualAllocEx(hProcess, NULL, strlen(DLL_PATH)+1, MEM_COMMIT, PAGE_READWRITE);
	DWORD nBytesWritten;

	if (!WriteProcessMemory(hProcess, lpDllAddress, DLL_PATH, strlen(DLL_PATH)+1, &nBytesWritten) || nBytesWritten == 0)
	{
		printf("Error: WriteProcessMemory! (%d)\n", GetLastError());
	}
	else
	{
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)llAddress, lpDllAddress, NULL, NULL);
		if (!hThread)
			printf("Error: CreateRemoteThread! (%d)\n", GetLastError());
		else
			CloseHandle(hThread);
	}     
	printf("Done!\n");
}
/*
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
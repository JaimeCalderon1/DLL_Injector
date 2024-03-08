#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD getProcId(const char* procName)
{
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!_stricmp(procEntry.szExeFile, procName))
				{
					pid = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
		CloseHandle(hSnap);
	}
	return pid;
}

int main()
{
	//const char* dllPath = "C:\\Users\\playerOne\\source\\repos\\ac_internal_dll\\Debug\\ac_internal_dll.dll";
	const char* dllPath = "C:\\Users\\playerOne\\source\\repos\\AssaultCubeTrainer\\Debug\\AssaultCubeTrainer.dll";
	const char* procName = "ac_client.exe";
	DWORD pid = 0;

	while (!pid)
	{
		pid = getProcId(procName);
		Sleep(30);
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hProc == NULL)
	{
		std::cout << "open proc fail\n";
		return EXIT_FAILURE;
	}

	// alloc memory in target process
	PVOID loc = VirtualAllocEx(hProc, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);

	// write DLL into target process
	WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, NULL);

	// call DLL
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, NULL);

	// Wait for the remote thread to complete
	WaitForSingleObject(hThread, INFINITE);

	// Get the exit code of the remote thread
	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);

	VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProc);
	
	std::cout << pid << '\n';
	std::cin.get();
	return 0;

	
}

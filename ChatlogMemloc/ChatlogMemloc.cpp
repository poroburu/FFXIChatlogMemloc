#include "stdafx.h"

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

/**
* @brief Obtains the process id of Final Fantasy XI. (pol.exe)
* @return The process id if found, 0 otherwise.
*/
DWORD getFinalFantasyProcessId(void)
{
	PROCESSENTRY32 pe32{ sizeof(PROCESSENTRY32) };

	auto handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (handle == INVALID_HANDLE_VALUE)
		return 0;

	if (!::Process32First(handle, &pe32))
	{
		::CloseHandle(handle);
		return 0;
	}

	do
	{
		if (wcscmp(pe32.szExeFile, L"horizon-loader.exe") == 0)
		{
			::CloseHandle(handle);
			return pe32.th32ProcessID;
		}
	} while (::Process32Next(handle, &pe32));

	::CloseHandle(handle);
	return 0;
}

/**
* @brief Obtains the process base address of FFXiMain.dll
*
* @param dwProcId  The process id to obtain the base address of.
* @return The process base address if found, 0 otherwise.
*/
DWORD getFinalFantasyMainBase(DWORD dwProcId)
{
	MODULEENTRY32 me32{ sizeof(MODULEENTRY32) };

	auto handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcId);
	if (handle == INVALID_HANDLE_VALUE)
		return 0;

	if (!::Module32First(handle, &me32))
	{
		::CloseHandle(handle);
		return 0;
	}

	do
	{
		if (wcscmp(me32.szModule, L"ffximain.dll") == 0)
		{
			::CloseHandle(handle);
			return (DWORD)me32.modBaseAddr;
		}
	} while (::Module32Next(handle, &me32));

	::CloseHandle(handle);
	return (DWORD)0;
}

/**
* @brief Obtains the process base size of FFXiMain.dll
*
* @param dwProcId  The process id to obtain the base address of.
* @return The process base size if found, 0 otherwise.
*/
DWORD getFinalFantasyMainSize(DWORD dwProcId)
{
	MODULEENTRY32 me32{ sizeof(MODULEENTRY32) };

	auto handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcId);
	if (handle == INVALID_HANDLE_VALUE)
		return 0;

	if (!::Module32First(handle, &me32))
	{
		::CloseHandle(handle);
		return 0;
	}

	do
	{
		if (wcscmp(me32.szModule, L"ffximain.dll") == 0)
		{
			::CloseHandle(handle);
			return (DWORD)me32.modBaseSize;
		}
	} while (::Module32Next(handle, &me32));

	::CloseHandle(handle);
	return (DWORD)0;
}

/**
* @brief Compares the given memory data against the given pattern using the desired mask.
*
* @param lpData            Pointer to the actual memory to be compared again.
* @param lpPattern         Pointer to the pattern to scan the memory for.
* @param pszMask           String containing the mask for the pattern being compared against.
*
* @return True when the pattern is found, false otherwise.
*/
static bool __stdcall MaskCompare(const unsigned char* lpData, const unsigned char* lpPattern, const char* pszMask)
{
	for (; *pszMask; ++pszMask, ++lpData, ++lpPattern)
		if (*pszMask == 'x' && *lpData != *lpPattern)
			return false;
	return (*pszMask) == NULL;
}

/**
* @brief Locates the given pattern inside the given data.
*
* @param lpData            The data to scan for our pattern within.
* @param nDataSize         The size of the data block to scan within.
* @param lpPattern         The pattern to compare the memory against.
* @param pszMask           String containing the mask for the pattern being compared against.
*
* @return Location of where the pattern was found, 0 otherwise.
*/
static DWORD __stdcall FindPattern(const unsigned char* lpData, unsigned int nDataSize, const unsigned char* lpPattern, const char* pszMask)
{
	for (unsigned int x = 0; x < nDataSize; x++)
		if (MaskCompare(lpData + x, lpPattern, pszMask))
			return (DWORD)(lpData + x);
	return 0;
}

/**
* @brief The main application entry point.
*
* @param argc  The number of arguments passed to this program.
* @param argv  The arguments passed to this program.
*
* @return Error code on succss of application.
*/
int main()
{
	std::cout << "===============================================" << std::endl;
	std::cout << "KParser Memloc Finder" << std::endl;
	std::cout << "by atom0s (c) 2014 [atom0s@live.com]" << std::endl;
	std::cout << "modified on 16 sept 2016" << std::endl;
	std::cout << "===============================================" << std::endl << std::endl;

	// Get the process id..
	auto procId = getFinalFantasyProcessId();
	if (procId == 0)
		return -1;
	std::cout << "[*] Found game process!				procId: " << std::dec << procId << "(dec) " << std::hex << procId << "(hex)" << std::endl;

	// Get the process base address..
	auto procBase = getFinalFantasyMainBase(procId);
	if (procBase == 0)
	{
		std::cout << "[ ] Run tool with admin rights." << std::endl << std::endl;
		std::cout << "Press Enter to exit." << std::endl;

		std::cin.sync();
		std::cin.ignore();
		
		return -1;
	}
	std::cout << "[*] Admin rights OK." << std::endl;
	std::cout << "[*] Found game process base!			procBase: " << std::hex << procBase << "(hex) " << std::endl;

	// Get the process base size..
	auto procSize = getFinalFantasyMainSize(procId);
	if (procSize == 0)
	{
		std::cout << "An error occured." << std::endl << std::endl;
		std::cout << "Press Enter to exit." << std::endl;

		std::cin.sync();
		std::cin.ignore();

		return -1;
	}
	std::cout << "[*] Obtained process base size!			procSize: " << std::hex << procSize << "(hex) " << std::endl;

	// Open the process for reading..
	auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, procId);
	if (handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "An error occured." << std::endl << std::endl;
		std::cout << "Press Enter to exit." << std::endl;

		std::cin.sync();
		std::cin.ignore();

		return -1;
	}
	std::cout << "[*] Obtained process handle for memory reading!" << std::endl;

	// Dump the process memory..
	auto procDump = new unsigned char[procSize + 1];
	auto xxx = (DWORD)procDump;
	std::cout << "						procDump: " << std::hex << xxx << "(hex) " << std::endl;

	::ReadProcessMemory(handle, (LPCVOID)procBase, procDump, procSize, NULL);

	// Find the chat pointer..
	auto tmp1 = FindPattern(procDump, procSize, (BYTE*)"\x8B\x0D\xFF\xFF\xFF\xFF\x85\xC9\x74\x0F\x8B\xFF\xFF\xFF\xFF\xFF\x8B", "xx????xxxxx?????x");
	if (tmp1 == NULL)
	{
		::CloseHandle(handle);
		delete[] procDump;
		std::cout << "[ ] No signature found." << std::endl << std::endl;
		std::cout << "Press Enter to exit." << std::endl;

		std::cin.sync();
		std::cin.ignore();

		return -1;
	}

	std::cout << "						tmp1 (8B0D????????85C9740F8B??????????8B): " << std::hex << tmp1 << "(hex) " << std::endl;

	// Readjust..
	auto tmp2 = tmp1 - (DWORD)procDump;
	std::cout << "						tmp2=tmp1-procDump: " << std::hex << tmp2 << "(hex) " << std::endl;
	std::cout << "[*] Found signature for chat!			ffximain.dll+" << std::hex << tmp2 << "(hex) " << std::endl;

	// Read the chat pointer..
	auto tmp3 = procBase + tmp2 + 2;
	std::cout << "						tmp3=procBase+tmp2+2: " << std::hex << tmp3 << "(hex) " << std::endl;
	auto tmp4 = 0;
	::ReadProcessMemory(handle, (LPCVOID)(tmp3), &tmp4, 4, NULL);
	std::cout << "						tmp4=reading memory at tmp3: " << std::hex << tmp4 << "(hex) " << std::endl;
	tmp4 = tmp4 + 12 - procBase;
	std::cout << "						final=tmp4+C(hex)-procBase: " << std::hex << tmp4 << "(hex) " << std::endl;
	std::cout << "[*] Chat Memory Offset: " << std::hex << tmp4 << std::endl << std::endl;
	std::cout << "Press Enter to exit." << std::endl;

	::CloseHandle(handle);
	delete[] procDump;

	std::cin.sync();
	std::cin.ignore();

    return 0;
}


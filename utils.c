#include "stdafx.h"

LONG _CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal)
{
	if (ppOriginal) {
		*ppOriginal = pTarget;
		return DetourAttach(ppOriginal, pDetour);
	}
	return DetourAttach(&pTarget, pDetour); // if the original function isn't needed, then it's likely I don't care about restoring it.
}

// https://stackoverflow.com/a/17457077

/*Convert Virtual Address to File Offset */
static DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

VOID FindApiSetDll(LPCWSTR fileName, ApiSetDllNameCallback f)
{
	HANDLE handle = CreateFile(fileName, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE)
		return;

	DWORD byteread, size = GetFileSize(handle, NULL);
	if (size) {
		PVOID virtualpointer = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
		if (virtualpointer) {
			if (ReadFile(handle, virtualpointer, size, &byteread, NULL)) {
				// Get pointer to NT header
				PIMAGE_NT_HEADERS ntheaders = (PIMAGE_NT_HEADERS)((LPBYTE)virtualpointer + (DWORD_PTR)((PIMAGE_DOS_HEADER)virtualpointer)->e_lfanew);
				PIMAGE_SECTION_HEADER       pSech = IMAGE_FIRST_SECTION(ntheaders);//Pointer to first section header
				PIMAGE_IMPORT_DESCRIPTOR    pImportDescriptor; //Pointer to import descriptor 
				__try
				{
					if (ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)/*if size of the table is 0 - Import Table does not exist */
					{
						pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)virtualpointer + \
							Rva2Offset(ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSech, ntheaders));
						LPSTR libname[MAX_PATH];
						SIZE_T i = 0;
						// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
						while (pImportDescriptor->Name)
						{
							libname[i] = (PCHAR)((DWORD_PTR)virtualpointer + Rva2Offset(pImportDescriptor->Name, pSech, ntheaders));
							if (!f(libname[i], fileName))
								break;
							pImportDescriptor++; //advance to next IMAGE_IMPORT_DESCRIPTOR
							i++;
						}

					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					;
				}
			}
			VirtualFree(virtualpointer, size, MEM_DECOMMIT);
		}
	}
	CloseHandle(handle);
}

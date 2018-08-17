#include "stdafx.h"
#include <malloc.h>

int __cdecl _callnewh(size_t size) {
	UNREFERENCED_PARAMETER(size);
	return 0;
}
void* __cdecl malloc(size_t _Size) {
	return HeapAlloc(GetProcessHeap(), 0, _Size);
}

void __cdecl free(void* _Block) {
	if (_Block)
		HeapFree(GetProcessHeap(), 0, _Block);
}

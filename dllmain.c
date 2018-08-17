#include "stdafx.h"

BOOL APIENTRY _DllMainCRTStartup( HMODULE hModule,
                       DWORD  dwReasonForCall,
                       LPVOID lpReserved
					 )
{
	UNREFERENCED_PARAMETER(lpReserved);

	switch (dwReasonForCall)
	{
	case DLL_PROCESS_ATTACH:
		__security_init_cookie();
		DisableThreadLibraryCalls(hModule);
#if 1
		GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)hModule, &g_hInstance);
#else
		// TODO DLL_PROCESS_DETACH
		g_hInstance = hModule;
#endif

		if (DetourTransactionBegin() == NO_ERROR) {
			if (DetourUpdateThread(GetCurrentThread()) == NO_ERROR) {
				DnsServerOverrider();
				DetourTransactionCommit();
			}
		}
		break;
	}
	return TRUE;
}


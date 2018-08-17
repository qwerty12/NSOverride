#include "stdafx.h"

// https://github.com/processhacker/processhacker/blob/master/phnt/include/ntregapi.h
#define REG_MAX_KEY_NAME_LENGTH 512
typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation, // KEY_BASIC_INFORMATION
    KeyNodeInformation, // KEY_NODE_INFORMATION
    KeyFullInformation, // KEY_FULL_INFORMATION
    KeyNameInformation, // KEY_NAME_INFORMATION
    KeyCachedInformation, // KEY_CACHED_INFORMATION
    KeyFlagsInformation, // KEY_FLAGS_INFORMATION
    KeyVirtualizationInformation, // KEY_VIRTUALIZATION_INFORMATION
    KeyHandleTagsInformation, // KEY_HANDLE_TAGS_INFORMATION
    KeyTrustInformation, // KEY_TRUST_INFORMATION
    KeyLayerInformation, // KEY_LAYER_INFORMATION
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_NAME_INFORMATION
{
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryKey(
	_In_ HANDLE KeyHandle,
	_In_ KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_writes_bytes_opt_(Length) PVOID KeyInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength
);

typedef RPC_STATUS(RPC_ENTRY *RPCBINDINGCREATEW)(RPC_BINDING_HANDLE_TEMPLATE_V1_W*, RPC_BINDING_HANDLE_SECURITY_V1_W*, RPC_BINDING_HANDLE_OPTIONS_V1*, RPC_BINDING_HANDLE*);
static RPCBINDINGCREATEW RpcBindingCreateWOrig = NULL;

typedef LSTATUS(APIENTRY *REGQUERYVALUEEXA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static REGQUERYVALUEEXA RegQueryValueExAAdvapi32Orig = NULL;
static REGQUERYVALUEEXA RegQueryValueExAApiSetOrig = NULL;

static LSTATUS APIENTRY RegQueryValueExAHooked(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData, REGQUERYVALUEEXA RegQueryValueExAOrig)
{
	DWORD Type;
	DWORD oldCbData = lpcbData ? *lpcbData : 0;
	LPDWORD lpNewType = lpType ? lpType : &Type;

	LSTATUS ret = RegQueryValueExAOrig(hKey, lpValueName, lpReserved, lpNewType, lpData, lpcbData);
	if ((ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA) && lpValueName && *lpNewType == REG_SZ && *lpcbData > 1 && !_stricmp(lpValueName, "NameServer")) { /* *lpcbData > 1 should be removed if you want the DNS server override to take place regardless of whether a custom DNS server has been set for the interface anyway */
		BYTE kni[sizeof(KEY_NAME_INFORMATION) + (REG_MAX_KEY_NAME_LENGTH * sizeof(WCHAR))];
		ULONG cbpkni = sizeof(kni);
		PKEY_NAME_INFORMATION pkni = (PKEY_NAME_INFORMATION)&kni;

		if (NT_SUCCESS(NtQueryKey((HANDLE)hKey, KeyNameInformation, pkni, cbpkni, &cbpkni)) && pkni->NameLength) {
			pkni->Name[pkni->NameLength] = L'\0';

			if (StrStrIW(pkni->Name, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\")) {
				DWORD nSize = GetEnvironmentVariableW(L"NAMESERVER", NULL, 0);
				if (nSize) {
					*lpcbData = nSize;
					if (ret == ERROR_MORE_DATA || oldCbData < nSize)
						return ERROR_MORE_DATA;

					nSize = GetEnvironmentVariableA("NAMESERVER", lpData, nSize);
				}

				if (!nSize) {
					*lpData = '\0';
					*lpcbData = 1;
					ret = ERROR_ACCESS_DENIED;
				}
			}
		}
	}

	return ret;
}

LSTATUS APIENTRY RegQueryValueExAAdvapi32HookDispatch(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	return RegQueryValueExAHooked(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData, RegQueryValueExAAdvapi32Orig);
}

LSTATUS APIENTRY RegQueryValueExAApiSetHookDispatch(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	return RegQueryValueExAHooked(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData, RegQueryValueExAApiSetOrig);
}

/* Prevent dnsapi.dll in the process from sending the queries to the DNSCache service, bypassing in-process name resolution */
RPC_STATUS RPC_ENTRY RpcBindingCreateWHook(RPC_BINDING_HANDLE_TEMPLATE_V1_W * Template, RPC_BINDING_HANDLE_SECURITY_V1_W * Security, RPC_BINDING_HANDLE_OPTIONS_V1 * Options, RPC_BINDING_HANDLE * Binding)
{
	if (Template && Template->StringEndpoint && !wcscmp(Template->StringEndpoint, L"DNSResolver"))
		return RPC_S_INTERFACE_NOT_FOUND;

	return RpcBindingCreateWOrig(Template, Security, Options, Binding);
}

static BOOL FindRegistryApiSetDll(LPCSTR libname, LPCWSTR importsname)
{
	UNREFERENCED_PARAMETER(importsname);

	if (PathMatchSpecA(libname, "api-ms-win-core-registry-l*.dll")) {
		CreateHook(GetProcAddress(LoadLibraryA(libname), "RegQueryValueExA"), RegQueryValueExAApiSetHookDispatch, &RegQueryValueExAApiSetOrig);
		return FALSE;
	}

	return TRUE;
}

VOID DnsServerOverrider()
{
	// NAMESERVER is a comma-separated list of IP addresses with no spaces whatsoever
	if (GetEnvironmentVariableW(L"NAMESERVER", NULL, 0) && GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
		CreateHook(RpcBindingCreateW, RpcBindingCreateWHook, &RpcBindingCreateWOrig);
		CreateHook(RegQueryValueExA, RegQueryValueExAAdvapi32HookDispatch, &RegQueryValueExAAdvapi32Orig);

		WCHAR fileName[MAX_PATH];
		if (GetSystemWindowsDirectoryW(fileName, ARRAYSIZE(fileName)) && SUCCEEDED(StringCchCatW(fileName, ARRAYSIZE(fileName), L"\\System32\\IPHLPAPI.dll")))
			FindApiSetDll(fileName, FindRegistryApiSetDll);
	}
}

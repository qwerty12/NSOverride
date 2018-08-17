// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

// Including SDKDDKVer.h defines the highest available Windows platform.

// If you wish to build your application for a previous Windows platform, include WinSDKVer.h and
// set the _WIN32_WINNT macro to the platform you wish to support before including SDKDDKVer.h.

#include <SDKDDKVer.h>

#define _DCRTIMP
#define _ACRTIMP

#define WIN32_NO_STATUS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#endif
#define WIN32_EXTRA_LEAN
#define NOGDICAPMASKS
#define NOWINSTYLES
#define NOSYSMETRICS
#define NOMENUS
#define NOICONS
#define NOKEYSTATES
#define NORASTEROPS
#define OEMRESOURCE
#define NOATOM
#define NOCOLOR
#define NODRAWTEXT
#define NOGDI
#define NOKERNEL
#define NONLS
#define NOMEMMGR
#define NOMETAFILE
#define NOMINMAX
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOTEXTMETRIC
#define NOWINOFFSETS
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX
#include <windows.h>
#undef WIN32_NO_STATUS
// Windows Header Files:
#include <strsafe.h>
#include <winternl.h>
#include <Shlwapi.h>

#include <detours.h>

#define CreateHook(pTarget, pDetour, ppOriginal) _CreateHook(pTarget, pDetour, (LPVOID*)ppOriginal)

#ifdef __cplusplus
extern "C" {
#endif

HMODULE g_hInstance;

LONG _CreateHook(LPVOID, LPVOID, LPVOID*);
VOID DnsServerOverrider();

typedef BOOL(*ApiSetDllNameCallback)(LPCSTR, LPCWSTR);
VOID FindApiSetDll(LPCWSTR fileName, ApiSetDllNameCallback f);

#ifdef __cplusplus
}
#endif

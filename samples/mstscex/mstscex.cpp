//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (simple.cpp of simple.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  This DLL will detour the Windows SleepEx API so that TimedSleep function
//  gets called instead.  TimedSleepEx records the before and after times, and
//  calls the real SleepEx API through the TrueSleepEx function pointer.
//

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#include "detours.h"

static FILE* g_LogFile = NULL;
const char* g_LogFileName = "C:\\wayk\\tmp\\mstscex.txt";

void OpenLog(const char* filename)
{
    g_LogFile = fopen(filename, "wb");
}

void CloseLog()
{
    fclose(g_LogFile);
}

int ConvertFromUnicode(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
                       LPSTR* lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar,
                       LPBOOL lpUsedDefaultChar)
{
	int status;
	BOOL allocate = FALSE;

	if (!lpWideCharStr)
		return 0;

	if (!lpMultiByteStr)
		return 0;

	if (cchWideChar == -1)
		cchWideChar = (int)(wcslen(lpWideCharStr) + 1);

	if (cbMultiByte == 0)
	{
		cbMultiByte =
		    WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, NULL, 0, NULL, NULL);
		allocate = TRUE;
	}
	else if (!(*lpMultiByteStr))
		allocate = TRUE;

	if (cbMultiByte < 1)
		return 0;

	if (allocate)
	{
		*lpMultiByteStr = (LPSTR)calloc(1, cbMultiByte + 1);

		if (!(*lpMultiByteStr))
		{
			return 0;
		}
	}

	status = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, *lpMultiByteStr,
	                             cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

	if ((status != cbMultiByte) && allocate)
	{
		status = 0;
	}

	if ((status <= 0) && allocate)
	{
		free(*lpMultiByteStr);
		*lpMultiByteStr = NULL;
	}

	return status;
}

int ConvertToUnicode(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
                     LPWSTR* lpWideCharStr, int cchWideChar)
{
	int status;
	BOOL allocate = FALSE;

	if (!lpMultiByteStr)
		return 0;

	if (!lpWideCharStr)
		return 0;

	if (cbMultiByte == -1)
	{
		size_t len = strnlen(lpMultiByteStr, INT_MAX);
		if (len >= INT_MAX)
			return 0;
		cbMultiByte = (int)(len + 1);
	}

	if (cchWideChar == 0)
	{
		cchWideChar = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, NULL, 0);
		allocate = TRUE;
	}
	else if (!(*lpWideCharStr))
		allocate = TRUE;

	if (cchWideChar < 1)
		return 0;

	if (allocate)
	{
		*lpWideCharStr = (LPWSTR)calloc(cchWideChar + 1, sizeof(WCHAR));

		if (!(*lpWideCharStr))
		{
			return 0;
		}
	}

	status = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, *lpWideCharStr,
	                             cchWideChar);

	if (status != cchWideChar)
	{
		if (allocate)
		{
			free(*lpWideCharStr);
			*lpWideCharStr = NULL;
			status = 0;
		}
	}

	return status;
}

INT (WINAPI * Real_GetAddrInfoExW)(
PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace, LPGUID lpNspId, const ADDRINFOEXW* hints,
PADDRINFOEXW* ppResult, struct timeval* timeout, LPOVERLAPPED lpOverlapped,
LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpHandle) = GetAddrInfoExW;

INT WINAPI Hook_GetAddrInfoExW(
    PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace, LPGUID lpNspId, const ADDRINFOEXW* hints,
    PADDRINFOEXW* ppResult, struct timeval* timeout, LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpHandle)
{
    fprintf(g_LogFile, "GetAddrInfoExW\n");
    return Real_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpHandle);
}

INT (WINAPI * Real_GetAddrInfoW)(PCWSTR pNodeName, PCWSTR pServiceName,
const ADDRINFOW *pHints, PADDRINFOW *ppResult) = GetAddrInfoW;

INT WINAPI Hook_GetAddrInfoW(PCWSTR pNodeNameW, PCWSTR pServiceName,
    const ADDRINFOW *pHints, PADDRINFOW *ppResult)
{
    int status;
    char* pNodeNameA = NULL;
    WCHAR* pNodeNameZ = NULL;
    ConvertFromUnicode(CP_UTF8, 0, pNodeNameW, -1, &pNodeNameA, 0, NULL, NULL);
    fprintf(g_LogFile, "GetAddrInfoW: %s\n", pNodeNameA);

    if (!strcmp(pNodeNameA, "IT-HELP-CA")) {
        ConvertToUnicode(CP_UTF8, 0, "IT-HELP-DC", -1, &pNodeNameZ, 0);
        pNodeNameW = pNodeNameZ;
    }

    status = Real_GetAddrInfoW(pNodeNameW, pServiceName, pHints, ppResult);

    free(pNodeNameA);
    free(pNodeNameZ);
    return status;
}

HMODULE (WINAPI * Real_LoadLibraryA)(LPCSTR lpLibFileName) = LoadLibraryA;

HMODULE Hook_LoadLibraryA(LPCSTR lpLibFileName)
{
    HMODULE hModule;

    fprintf(g_LogFile, "LoadLibraryA: %s\n", lpLibFileName);

    hModule = Real_LoadLibraryA(lpLibFileName);

    return hModule;
}

HMODULE (WINAPI * Real_LoadLibraryW)(LPCWSTR lpLibFileName) = LoadLibraryW;

HMODULE Hook_LoadLibraryW(LPCWSTR lpLibFileName)
{
    HMODULE hModule;
    char* lpLibFileNameA = NULL;
    ConvertFromUnicode(CP_UTF8, 0, lpLibFileName, -1, &lpLibFileNameA, 0, NULL, NULL);

    fprintf(g_LogFile, "LoadLibraryW: %s\n", lpLibFileNameA);

    if (strstr(lpLibFileNameA, "mstscax.dll")) {
        fprintf(g_LogFile, "LoadLibraryW: loading rdclientax.dll instead\n");
        lpLibFileNameA = _strdup("C:\\Users\\mamoreau\\Documents\\Reversing\\msrdc\\rdclientax.dll");
        hModule = Real_LoadLibraryA(lpLibFileNameA);
    } else {
        hModule = Real_LoadLibraryW(lpLibFileName);
    }

    free(lpLibFileNameA);

    return hModule;
}

HMODULE (WINAPI * Real_LoadLibraryExA)(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) = LoadLibraryExA;

HMODULE Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE hModule;

    fprintf(g_LogFile, "LoadLibraryExA: %s\n", lpLibFileName);

    hModule = Real_LoadLibraryExA(lpLibFileName, hFile, dwFlags);
    
    return hModule;
}

HMODULE (WINAPI * Real_LoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) = LoadLibraryExW;

HMODULE Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE hModule;
    char* lpLibFileNameA = NULL;
    ConvertFromUnicode(CP_UTF8, 0, lpLibFileName, -1, &lpLibFileNameA, 0, NULL, NULL);

    fprintf(g_LogFile, "LoadLibraryExW: %s\n", lpLibFileNameA);

    if (strstr(lpLibFileNameA, "mstscax.dll")) {
        fprintf(g_LogFile, "LoadLibraryExW: loading rdclientax.dll instead\n");
        lpLibFileNameA = _strdup("C:\\Users\\mamoreau\\Documents\\Reversing\\msrdc\\rdclientax.dll");
        hModule = Real_LoadLibraryExA(lpLibFileNameA, hFile, dwFlags);
    } else {
        hModule = Real_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    }

    free(lpLibFileNameA);

    return hModule;
}

LSTATUS (WINAPI * Real_RegQueryValueExW)(HKEY hKey, LPCWSTR lpValueName,
    LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) = RegQueryValueExW;

LSTATUS Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName,
    LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LSTATUS status;

    status = Real_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    if ((status == ERROR_SUCCESS) && lpType && lpData) {
        fprintf(g_LogFile, "RegQueryValueExW! %d\n", (int) *lpType);
        if ((*lpType == REG_EXPAND_SZ) || (*lpType == REG_SZ) || (*lpType == 0)) {

            WCHAR* regValueW = (WCHAR*) lpData;
            char* regValueA = NULL;
            ConvertFromUnicode(CP_UTF8, 0, regValueW, -1, &regValueA, 0, NULL, NULL);

            if (strstr(regValueA, "mstscax.dll")) {
                //fprintf(g_LogFile, "RegQueryValueExW: -> %s\n", regValueA);
            }

            free(regValueA);
        }
    }

    return status;
}

PSecurityFunctionTableW (SEC_ENTRY * Real_InitSecurityInterfaceW)(void) = InitSecurityInterfaceW;

PSecurityFunctionTableW SEC_ENTRY Hook_InitSecurityInterfaceW(void)
{
    PSecurityFunctionTableW pTable = NULL;
    fprintf(g_LogFile, "InitSecurityInterfaceW\n");
    pTable = Real_InitSecurityInterfaceW();
    return pTable;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        OpenLog(g_LogFileName);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)Real_GetAddrInfoExW, Hook_GetAddrInfoExW);
        DetourAttach(&(PVOID&)Real_GetAddrInfoW, Hook_GetAddrInfoW);
        DetourAttach(&(PVOID&)Real_LoadLibraryA, Hook_LoadLibraryA);
        DetourAttach(&(PVOID&)Real_LoadLibraryW, Hook_LoadLibraryW);
        DetourAttach(&(PVOID&)Real_LoadLibraryExA, Hook_LoadLibraryExA);
        DetourAttach(&(PVOID&)Real_LoadLibraryExW, Hook_LoadLibraryExW);
        DetourAttach(&(PVOID&)Real_RegQueryValueExW, Hook_RegQueryValueExW);
        DetourAttach(&(PVOID&)Real_InitSecurityInterfaceW, Hook_InitSecurityInterfaceW);
        error = DetourTransactionCommit();
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_GetAddrInfoExW, Hook_GetAddrInfoExW);
        DetourDetach(&(PVOID&)Real_GetAddrInfoW, Hook_GetAddrInfoW);
        DetourDetach(&(PVOID&)Real_LoadLibraryA, Hook_LoadLibraryA);
        DetourDetach(&(PVOID&)Real_LoadLibraryW, Hook_LoadLibraryW);
        DetourDetach(&(PVOID&)Real_LoadLibraryExA, Hook_LoadLibraryExA);
        DetourDetach(&(PVOID&)Real_LoadLibraryExW, Hook_LoadLibraryExW);
        DetourDetach(&(PVOID&)Real_RegQueryValueExW, Hook_RegQueryValueExW);
        DetourDetach(&(PVOID&)Real_InitSecurityInterfaceW, Hook_InitSecurityInterfaceW);
        
        error = DetourTransactionCommit();
        CloseLog();
    }

    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.

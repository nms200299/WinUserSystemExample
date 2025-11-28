#include "pch.h"
#include "windows.h"

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ReasonCode, LPVOID lpReserved) {
    switch (ReasonCode) {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"DLL Injection Success !", L"HookDLL", MB_OK);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
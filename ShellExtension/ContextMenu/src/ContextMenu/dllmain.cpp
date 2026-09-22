// dllmain.cpp : DllMain의 구현입니다.

#include "pch.h"
#include "framework.h"
#include "resource.h"
#include "ContextMenu_i.h"
#include "dllmain.h"

CContextMenuModule _AtlModule;

// DLL 진입점입니다.
extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	hInstance;
	return _AtlModule.DllMain(dwReason, lpReserved);
}

/*
Title : ALL-IN-ONE IAT 후킹 테스트
Summary : 스스로의 IAT를 조작하여 IAT 후킹을 테스트합니다.
*/ 

#include <stdio.h>
#include <windows.h>

typedef int (WINAPI* PFMESSAGEBOXW)(
	HWND     hWnd,
	LPCWSTR  lpText,
	LPCWSTR  lpCaption,
	UINT     uType
	);

typedef int (WINAPI* PFMESSAGEBOXA)(
	HWND     hWnd,
	LPCSTR  lpText,
	LPCSTR  lpCaption,
	UINT     uType
	);

FARPROC pOrgMessageBoxW;
FARPROC pOrgMessageBoxA;

void Msg() {
	MessageBoxW(NULL, L"TEST", L"TEST", MB_OK | MB_ICONASTERISK);
	MessageBoxA(NULL, "TEST", "TEST", MB_OK | MB_ICONASTERISK);
} // 테스트 함수

int WINAPI MessageBoxW_Hook(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType) {
	if (((PFMESSAGEBOXW)pOrgMessageBoxW)(NULL,
		L"This MessageBoxW API was intercepted by IAT Hook\nDo you want to see the actual message?\n",
		L"IAT Hook",
		MB_YESNO | MB_ICONQUESTION) == IDYES) {
		return ((PFMESSAGEBOXW)pOrgMessageBoxW)(hWnd, lpText, lpCaption, uType);
	}
	return IDNO;
} // MessageBoxW 후킹

int WINAPI MessageBoxA_Hook(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType) {
	if (((PFMESSAGEBOXA)pOrgMessageBoxA)(NULL,
		"This MessageBoxA API was intercepted by IAT Hook\nDo you want to see the actual message?\n",
		"IAT Hook",
		MB_YESNO | MB_ICONQUESTION) == IDYES) {
		return ((PFMESSAGEBOXA)pOrgMessageBoxA)(hWnd, lpText, lpCaption, uType);
	}
	return IDNO;
} // MessageBoxA 후킹


BOOL IatHooking(LPCSTR pcszDllName, PROC pFnBefore, PROC pFnAfter) {
	HMODULE hMod;
	hMod = GetModuleHandle(NULL);

	PBYTE pAddr;
	pAddr = (PBYTE)hMod;
	pAddr += *((DWORD*)&pAddr[0x3C]);
	// IMAGE_NT_HEADER의 시작 주소로 이동합니다.
	// (IMAGE_DOS_HEADER의 e_lfanew 값 4바이트를 더하기 할당)

	DWORD dwRVA;
#ifdef _WIN64
	dwRVA = *((DWORD*)&pAddr[0x90]); // PE64
#else
	dwRVA = *((DWORD*)&pAddr[0x80]); // PE32
#endif
	// IMAGE_NT_HEADER에 명시된 IDT(IMAGE_IMPORT_DESCRIPTOR) 주소를 구합니다.

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hMod + dwRVA);
	// IDT(IMAGE_IMPORT_DESCRIPTOR)의 VA를 구합니다.

	for (; pImportDesc->Name; pImportDesc++) {
		LPCSTR pcszIatDllName = (LPCSTR)((DWORD_PTR)hMod + (DWORD)pImportDesc->Name);
		// IDT의 DLL Name VA를 구합니다.
		if (!(_stricmp(pcszIatDllName, pcszDllName))) {
			// 후킹 대상의 DLL인지 대소문자 구분없이 문자열 비교합니다.
			PIMAGE_THUNK_DATA pThunk;
			pThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hMod + (DWORD)pImportDesc->FirstThunk);
			// IAT(IDT의 FirstThunk) VA를 구합니다.

			for (; pThunk->u1.Function; pThunk++) {
				// 임포트된 함수를 순회합니다. (NULL이면 목록이 종료됨을 의미)
				if (pThunk->u1.Function == (DWORD_PTR)pFnBefore) {

					// IAT에 로드된 함수 주소와 후킹 대상 함수 주소가 일치하는지 비교합니다.
					DWORD dwVirProtect;
					VirtualProtect((LPVOID)&pThunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &dwVirProtect);
					// IAT는 Read-only 속성으로 로드되기에 Read/Write 속성으로 변경 (sizeof(LPVOID)로 x86/64 대응)
					pThunk->u1.Function = (DWORD_PTR)pFnAfter;
					VirtualProtect((LPVOID)&pThunk->u1.Function, sizeof(LPVOID), dwVirProtect, &dwVirProtect);
					// 다시 Read-only 속성으로 원상 복구
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}



int main() {
	printf("IAT 후킹 전\n");
	Msg(); // IAT 후킹 전

	pOrgMessageBoxW = GetProcAddress(GetModuleHandleA("USER32.dll"), "MessageBoxW");
	IatHooking("USER32.dll", pOrgMessageBoxW, (PROC)MessageBoxW_Hook);
	pOrgMessageBoxA = GetProcAddress(GetModuleHandleA("USER32.dll"), "MessageBoxA");
	IatHooking("USER32.dll", pOrgMessageBoxA, (PROC)MessageBoxA_Hook);
	
	printf("IAT 후킹 후\n");
	Msg(); // IAT 후킹 후
	system("pause");
}

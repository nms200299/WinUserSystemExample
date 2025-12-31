/*
Title : EAT 후킹 타겟 프로그램
Summary : 테스트를 위해 DLL 인젝션 당할 프로그램입니다.
*/

#include <windows.h>
#include <stdio.h>

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

void test() {
	HMODULE hMod;
	hMod = LoadLibrary(L"user32.dll");
	if (!hMod) return;

	PFMESSAGEBOXW pMessageBoxW = (PFMESSAGEBOXW)GetProcAddress(hMod, "MessageBoxW");
	PFMESSAGEBOXA pMessageBoxA = (PFMESSAGEBOXA)GetProcAddress(hMod, "MessageBoxA");

	pMessageBoxW(NULL, L"TEST", L"TEST", MB_OK | MB_ICONASTERISK);
	pMessageBoxA(NULL, "TEST", "TEST", MB_OK | MB_ICONASTERISK);

	FreeLibrary(hMod);
} // 테스트 함수

int main() {
	printf("[EAT 후킹 테스트]\n");
	printf("EAT 후킹 전\n");
	test(); // EAT 후킹 전 테스트
	printf("EAT 후킹 후\n");
	test(); // EAT 후킹 후 테스트
	system("pause");
} // 테스트용 프로그램 (MessageBoxW/A 구분)
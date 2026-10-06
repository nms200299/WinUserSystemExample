/*
Title : ALL-IN-ONE Detours 후킹 테스트
Summary : 자기 자신 프로세스를 대상으로 Detours 후킹을 테스트합니다.
*/ 

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include "detours.h"

#ifdef _WIN64
#pragma comment(lib, "..\\lib.X64\\detours.lib")
#else
#pragma comment(lib, "..\\lib.X86\\detours.lib")
#endif


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


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* PFZWQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength
);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE  Reserved1[48];
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2[2];
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4[2];
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved5[6];
} SYSTEM_PROCESS_INFORMATION;

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
PFZWQUERYSYSTEMINFORMATION g_FnOrgZwQuerySystemInformation = (PFZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQuerySystemInformation");
PFMESSAGEBOXW g_FnOrgMessageBoxW = (PFMESSAGEBOXW)GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
PFMESSAGEBOXA g_FnOrgMessageBoxA = (PFMESSAGEBOXA)GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxA");

//#############################################################################################


void ZwQuerySystemInformation_TEST() {
	ULONG size = 0;
	NTSTATUS status;
	PFZWQUERYSYSTEMINFORMATION pFnOrgZwQuerySystemInformation = (PFZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQuerySystemInformation");
	status = pFnOrgZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);
	PBYTE buffer = (PBYTE)malloc(size);
	status = pFnOrgZwQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
	if (!NT_SUCCESS(status)) {
		printf("\tZwQuerySystemInformation Failed : 0x%X\n", status);
	}
	else {
		printf("\tZwQuerySystemInformation Successed : 0x%X\n", status);
	}
	free(buffer);
}

void TEST() {
	HMODULE hMod;
	hMod = LoadLibrary(L"user32.dll");
	if (!hMod) return;
	PFMESSAGEBOXW pMessageBoxW = (PFMESSAGEBOXW)GetProcAddress(hMod, "MessageBoxW");
	PFMESSAGEBOXA pMessageBoxA = (PFMESSAGEBOXA)GetProcAddress(hMod, "MessageBoxA");
	pMessageBoxW(NULL, L"Explicit MessageBoxW TEST", L"TEST", MB_OK | MB_ICONASTERISK);
	pMessageBoxA(NULL, "Explicit MessageBoxA TEST", "TEST", MB_OK | MB_ICONASTERISK);
	FreeLibrary(hMod);
	// Explicit API 후킹 테스트

	MessageBoxW(NULL, L"Implicit MessageBoxW TEST", L"TEST", MB_OK | MB_ICONASTERISK);
	MessageBoxA(NULL, "Implicit MessageBoxA TEST", "TEST", MB_OK | MB_ICONASTERISK);
	// Implicit API 후킹 테스트

	ZwQuerySystemInformation_TEST();
	// Zw API 후킹 테스트
}

// #########################################################################################

NTSTATUS NTAPI ZwQuerySystemInformation_Hook(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength
){
	return 0xC0000001; // STATUS_UNSUCCESSFUL
} // ZwQuerySystemInformation 후킹


int WINAPI MessageBoxW_Hook(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType) {

	FARPROC OrgFuncCallVA = (FARPROC)g_FnOrgMessageBoxW;
	if (((PFMESSAGEBOXW)OrgFuncCallVA)(NULL,
		L"This MessageBoxW API was intercepted by Detours Hook\nDo you want to see the actual message?\n",
		L"Detours Hook",
		MB_YESNO | MB_ICONQUESTION) == IDYES) {
		((PFMESSAGEBOXW)OrgFuncCallVA)(hWnd, lpText, lpCaption, uType);
	}
	return IDNO;
} // MessageBoxW 후킹


int WINAPI MessageBoxA_Hook(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType) {
	FARPROC OrgFuncCallVA = (FARPROC)g_FnOrgMessageBoxA;
	if (((PFMESSAGEBOXA)OrgFuncCallVA)(NULL,
		"This MessageBoxA API was intercepted by Detours Hook\nDo you want to see the actual message?\n",
		"Detours Hook",
		MB_YESNO | MB_ICONQUESTION) == IDYES) {
		((PFMESSAGEBOXA)OrgFuncCallVA)(hWnd, lpText, lpCaption, uType);
	}
	return IDNO;
} // MessageBoxA 후킹



BOOL DetoursHook() {
	LONG State;
	// DetourRestoreAfterWith();
	// DLL의 경우, withdll.exe를 통해 삽입되었으면 IAT를 복구해줌

	State = DetourTransactionBegin();
	if (State != NO_ERROR) {
		printf("[%s:%d][%s] DetourTransactionBegin Failed !\n", __FILE__, __LINE__, __FUNCTION__);
		return FALSE;
	} // Detours 작업을 트랜잭션으로 묶어서 시작

	State = DetourUpdateThread(GetCurrentThread());
	if (State != NO_ERROR) {
		printf("[%s:%d][%s] DetourUpdateThread Failed !\n", __FILE__, __LINE__, __FUNCTION__);
		return FALSE;
	} // 대상 스레드의 실행 상태를 트랜잭션에 반영

	State = DetourAttach(&(PVOID&)g_FnOrgZwQuerySystemInformation, ZwQuerySystemInformation_Hook);
	if (State != NO_ERROR) printf("[%s:%d][%s] DetourAttach(ZwQuerySystemInformation_Hook) Failed !\n", __FILE__, __LINE__, __FUNCTION__);
	State = DetourAttach(&(PVOID&)g_FnOrgMessageBoxW, MessageBoxW_Hook);
	if (State != NO_ERROR) printf("[%s:%d][%s] DetourAttach(MessageBoxW_Hook) Failed !\n", __FILE__, __LINE__, __FUNCTION__);
	State = DetourAttach(&(PVOID&)g_FnOrgMessageBoxA, MessageBoxA_Hook);
	if (State != NO_ERROR) printf("[%s:%d][%s] DetourAttach(MessageBoxA_Hook) Failed !\n", __FILE__, __LINE__, __FUNCTION__);
	// 원본 함수를 후킹 함수에 연결

	State = DetourTransactionCommit();
	if (State != NO_ERROR) {
		printf("[%s:%d][%s] DetourTransactionCommit Failed !\n", __FILE__, __LINE__, __FUNCTION__);
		return FALSE;
	} // Detours 트랜잭션 작업을 적용

	return TRUE;
}

BOOL DetoursUnHook() {
	LONG State;
	State = DetourTransactionBegin();
	if (State != NO_ERROR) {
		printf("[%s:%d][%s] DetourTransactionBegin Failed !\n", __FILE__, __LINE__, __FUNCTION__);
		return FALSE;
	} // Detours 작업을 트랜잭션으로 묶어서 시작

	State = DetourUpdateThread(GetCurrentThread());
	if (State != NO_ERROR) {
		printf("[%s:%d][%s] DetourUpdateThread Failed !\n", __FILE__, __LINE__, __FUNCTION__);
		return FALSE;
	} // 대상 스레드의 실행 상태를 트랜잭션에 반영

	State = DetourDetach(&(PVOID&)g_FnOrgZwQuerySystemInformation, ZwQuerySystemInformation_Hook);
	if (State != NO_ERROR) printf("[%s:%d][%s] DetourDetach(ZwQuerySystemInformation_Hook) Failed !\n", __FILE__, __LINE__, __FUNCTION__);
	State = DetourDetach(&(PVOID&)g_FnOrgMessageBoxW, MessageBoxW_Hook);
	if (State != NO_ERROR) printf("[%s:%d][%s] DetourDetach(MessageBoxW_Hook) Failed !\n", __FILE__, __LINE__, __FUNCTION__);
	State = DetourDetach(&(PVOID&)g_FnOrgMessageBoxA, MessageBoxA_Hook);
	if (State != NO_ERROR) printf("[%s:%d][%s] DetourDetach(MessageBoxA_Hook) Failed !\n", __FILE__, __LINE__, __FUNCTION__);
	// 후킹 함수를 원본 함수로 복원

	State = DetourTransactionCommit();
	if (State != NO_ERROR) {
		printf("[%s:%d][%s] DetourTransactionCommit Failed !\n", __FILE__, __LINE__, __FUNCTION__);
		return FALSE;
	} // Detours 트랜잭션 작업을 적용

	return TRUE;
}



int _tmain() {	
	printf("[Detours 후킹 전]\n");
	TEST(); // Detours 후킹 전

	printf("\n[Detours 후킹 후]\n");
	if (DetoursHook()) printf("DetoursHook Success!\n");
	else printf("DetoursHook Fail!");
	TEST(); // Detours 후킹 후

	printf("\n[Detours 언훅 후]\n");
	if (DetoursUnHook()) printf("DetoursUnHook Success!\n");
	else printf("DetoursUnHook Fail!");
	TEST(); // Detours 언훅 후

	system("pause");

}

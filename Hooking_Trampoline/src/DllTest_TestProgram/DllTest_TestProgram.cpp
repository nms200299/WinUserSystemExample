/*
Title : Trampolie 후킹 타겟 프로그램
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

PFZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (PFZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQuerySystemInformation");

void ZwQuerySystemInformation_TEST() {
	ULONG size = 0;
	NTSTATUS status;
	status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);
	PBYTE buffer = (PBYTE)malloc(size);
	status = ZwQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
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

int main() {
	printf("[Trampoline 후킹 전]\n");
	TEST(); // Trampoline 후킹 전
	system("pause");

	printf("[Trampoline 후킹 후]\n");
	TEST(); // Trampoline 후킹 후
	system("pause");

} // 테스트용 프로그램

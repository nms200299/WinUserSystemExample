/*
Title : DLL용 Trampoline 후킹 테스트
Summary : DLL 인젝션 시, 타겟 프로세스의 API를 Trampoline 후킹 합니다.
*/


#include <tchar.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <intrin.h>

#include <tlhelp32.h>
#ifdef _WIN64
#include <hde64.h>
#else
#include <hde32.h>
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

PFZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (PFZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQuerySystemInformation");

//#############################################################################################

#pragma warning(disable : 26812) // C-style enum 강제
typedef enum {
	X86_5BYTE,
	X86_7BYTE,
	HOOK_OPT_MARKER,
	X64_12BYTE_REGSTER,
	X64_14BYTE_STACK,
	X64_14BYTE_RIP
} HookOpt;
typedef enum {
	TRAM_SELF_RECOVER = 0,
	TRAM_ALLOC = 1
} TramOpt;


#define MAX_SC 32
typedef struct {
	FARPROC pOrgVA;
	FARPROC pbAllocVA;
	BYTE pbOrgShellCode[MAX_SC];
	BYTE pbModShellCode[MAX_SC];
	BYTE pbAllocShellCode[MAX_SC];
	BYTE bShellCodeSize;
	BYTE bHookOpt;
	BYTE bTramOpt;
	DWORD g_dwTlsIndex;
	volatile LONG g_HookLock;
} TramStruct;


TramStruct CtxMessageBoxW;
TramStruct CtxMessageBoxA;
TramStruct CtxZwQuerySystemInformation;

FARPROC VirtualAllocProbing(PBYTE pbBaseAddr, DWORD_PTR pbMaxSearchIdx, BYTE bAllocSize) {
	PBYTE pbAllocAddr = NULL;
	DWORD_PTR pbSearchAddr = (DWORD_PTR)pbBaseAddr;
	// 포인터의 오버/언더플로는 컴파일러가 UB(Undefined Behavior)로 간주하기에 DWORD_PTR로 형변환하여 연산
	DWORD_PTR pbSearchIdx = 0;
	while ((pbAllocAddr == NULL) && (pbSearchIdx <= pbMaxSearchIdx)) {
		pbSearchAddr -= bAllocSize;
		if (pbSearchAddr > (DWORD_PTR)pbBaseAddr) break; // 역방향 탐색에서 언더플로우 발생 시, 탈출
		pbAllocAddr = (PBYTE)VirtualAlloc((PBYTE)pbSearchAddr, bAllocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		pbSearchIdx += bAllocSize;
	} // pbBaseAddr에서 역방향으로 pbMaxSearchIdx만큼 할당 가능 주소 탐색

	pbSearchAddr = (DWORD_PTR)pbBaseAddr;
	pbSearchIdx = 0;
	while ((pbAllocAddr == NULL) && (pbSearchIdx <= pbMaxSearchIdx)) {
		pbSearchAddr += bAllocSize;
		if (pbSearchAddr < (DWORD_PTR)pbBaseAddr) break; // 정방향 탐색에서 오버플로우 발생 시, 탈출
		pbAllocAddr = (PBYTE)VirtualAlloc((PBYTE)pbSearchAddr, bAllocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		pbSearchIdx += bAllocSize;
	} // pbBaseAddr에서 정방향으로 pbMaxSearchIdx만큼 할당 가능 주소 탐색

	printf("\t\tAllocate memory : %p...\n", pbAllocAddr);
	return (FARPROC)pbAllocAddr;
}

#ifdef _WIN64
bool RipRelocation(PBYTE pbOrgVA, PBYTE pbAllocVA, BYTE bShellCodeSize) {
	BYTE SumSize = 0;
	PBYTE pbLoopVA = pbAllocVA;
	while (SumSize < bShellCodeSize) {
		hde64s hs;
		hde64_disasm(pbLoopVA, &hs);
		SumSize += hs.len;
		pbLoopVA += hs.len;
		if ((hs.flags & F_MODRM) &&
			(hs.modrm_mod == 0) &&
			(hs.modrm_rm == 5)) {
			// RIP-relative 명령어인 경우

			if (hs.flags & F_DISP8) return FALSE;
			if (hs.flags & F_DISP16) return FALSE;
			// 주소 공간 할당 문제로 disp32만 처리

			if (hs.flags & F_DISP32) {
				PBYTE ripOffset = pbOrgVA + (int32_t)hs.disp.disp32 + SumSize;
				printf("\t\tOrgRip : %p(RIP) + %d(VAL) = %p(RESULT)\n", pbOrgVA + SumSize, hs.disp.disp32, ripOffset);
				INT64 ripDiff = (INT64)ripOffset - (INT64)(pbAllocVA + SumSize);
				if (ripDiff < INT32_MIN || ripDiff > INT32_MAX) {
					return FALSE;
				} // 2GB 범위를 벗어나면 FALSE 리턴

				INT32 ripDist = (INT32)(ripOffset - (pbAllocVA + SumSize));
				printf("\t\tModRip : %p(RIP) + %d(VAL) = %p(RESULT)\n", pbAllocVA + SumSize, ripDist, (pbAllocVA + SumSize + ripDist));
				// 할당된 주소에서 부터 RIP 거리 재계산

				BYTE immSize = 0;
				if (hs.flags & F_IMM8) immSize = 1;      // F_IMM8
				else if (hs.flags & F_IMM16) immSize = 2; // F_IMM16
				else if (hs.flags & F_IMM32) immSize = 4; // F_IMM32
				else if (hs.flags & F_IMM64) immSize = 8; // F_IMM64
				PBYTE pbDispAddr = pbLoopVA - sizeof(int32_t) - immSize;
				// 명령어에 추가적인 IMM이 있는지에 따라 dips32 명령어 위치 계산

				memcpy(pbDispAddr, &ripDist, sizeof(INT32));
			}
		}
	}
	return TRUE;
}
#endif

__forceinline void AcquireSpinLock(volatile LONG* lock)
{
	while (InterlockedCompareExchange(lock, 1, 0) != 0) {
		YieldProcessor(); // PAUSE
	}
}

__forceinline void ReleaseSpinLock(volatile LONG* lock)
{
	InterlockedExchange(lock, 0);
}

FARPROC TramHookWrite(TramStruct* pTramStruct, BOOL bHookFuncFlag, BOOL bRecoverFlag) {
	// cf1. ntdll.dll은 커널, 유저모드 진입/복귀 경로로 사용됨으로 EXECUTE 불가(NX) 시, 즉시 Access Violation 발생 (Windows 8.1 <=)
	if (bHookFuncFlag) {
		if (pTramStruct->bHookOpt == X86_7BYTE) return pTramStruct->pOrgVA; // X86_7BYTE 패치는 원본 코드의 Self-Restoring이 필요 없음
		if (pTramStruct->pbAllocVA) return pTramStruct->pbAllocVA; // 공간 할당으로 인한 Multi-stage Trampoline은 원본 코드의 Self-Restoring이 필요 없음
	}

	DWORD flOldProtect;
	if (bRecoverFlag) {
		AcquireSpinLock(&pTramStruct->g_HookLock);
		if (pTramStruct->bHookOpt == X86_7BYTE) {
			pTramStruct->pOrgVA = (FARPROC)((DWORD_PTR)pTramStruct->pOrgVA - 7);
		} // 덮어쓴 7바이트를 복구하기 위해 핫패치 영역으로 오프셋을 옮긴다.
		VirtualProtect((LPVOID)pTramStruct->pOrgVA, pTramStruct->bShellCodeSize, PAGE_EXECUTE_READWRITE, &flOldProtect); // cf1. 참고
		memcpy((PVOID)(pTramStruct->pOrgVA), &(pTramStruct->pbOrgShellCode[0]), pTramStruct->bShellCodeSize);
		VirtualProtect((LPVOID)pTramStruct->pOrgVA, pTramStruct->bShellCodeSize, flOldProtect, &flOldProtect);
		MemoryBarrier();
		FlushInstructionCache(GetCurrentProcess(), pTramStruct->pOrgVA, pTramStruct->bShellCodeSize);
		// I-Cache 무력화
		ReleaseSpinLock(&pTramStruct->g_HookLock);

		if ((!bHookFuncFlag) && (pTramStruct->pbAllocVA != NULL)) {
			printf("\tFree memory : %p\n", pTramStruct->pbAllocVA);
			VirtualFree(pTramStruct->pbAllocVA, 0, MEM_RELEASE);
			pTramStruct->pbAllocVA = NULL;
		} // pbAllocVA이 할당 상태면 할당 해제

		if (pTramStruct->g_dwTlsIndex != TLS_OUT_OF_INDEXES) {
			TlsFree(pTramStruct->g_dwTlsIndex);
			pTramStruct->g_dwTlsIndex = TLS_OUT_OF_INDEXES;
		} // TlsIndex가 할당 상태면 할당 해제


		return pTramStruct->pOrgVA;
	}
	else {
		AcquireSpinLock(&pTramStruct->g_HookLock);
		VirtualProtect((LPVOID)pTramStruct->pOrgVA, pTramStruct->bShellCodeSize, PAGE_EXECUTE_READWRITE, &flOldProtect); // cf1. 참고
		memcpy((PVOID)(pTramStruct->pOrgVA), &(pTramStruct->pbModShellCode[0]), pTramStruct->bShellCodeSize);
		VirtualProtect((LPVOID)pTramStruct->pOrgVA, pTramStruct->bShellCodeSize, flOldProtect, &flOldProtect);
		MemoryBarrier();
		FlushInstructionCache(GetCurrentProcess(), pTramStruct->pOrgVA, pTramStruct->bShellCodeSize);
		ReleaseSpinLock(&pTramStruct->g_HookLock);

		if (pTramStruct->bHookOpt == X86_7BYTE) {
			pTramStruct->pOrgVA = (FARPROC)((DWORD_PTR)pTramStruct->pOrgVA + 7);
			return pTramStruct->pOrgVA;
		} // 7바이트 패치 이후 실제 원본 API가 실행될 수 있는 위치로 오프셋을 옮긴다.

		if (pTramStruct->bTramOpt) {
#ifdef _WIN64
			BYTE RipJmpX64[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x88 ,0x77 ,0x66 ,0x55, 0x44 ,0x33 ,0x22 ,0x11 };
			// (JMP QWORD PTR [RIP+0]), (DQ 0x1122334455667788)
			BYTE bAllocSize = pTramStruct->bShellCodeSize + sizeof(RipJmpX64);
			pTramStruct->pbAllocVA = VirtualAllocProbing((PBYTE)pTramStruct->pOrgVA, 0x7FFFFFFF, bAllocSize);
			if (pTramStruct->pbAllocVA != NULL) {
				PBYTE pbNextOffset = (PBYTE)pTramStruct->pOrgVA + (pTramStruct->bShellCodeSize);
				memcpy(&(RipJmpX64[6]), &pbNextOffset, sizeof(DWORD_PTR));
				memcpy((PVOID)(pTramStruct->pbAllocVA), &(pTramStruct->pbOrgShellCode[0]), pTramStruct->bShellCodeSize);
				memcpy((PVOID)((PBYTE)pTramStruct->pbAllocVA + pTramStruct->bShellCodeSize), &(RipJmpX64[0]), sizeof(RipJmpX64));
				if (!RipRelocation((PBYTE)pTramStruct->pOrgVA, (PBYTE)pTramStruct->pbAllocVA, pTramStruct->bShellCodeSize)) {
					VirtualFree(pTramStruct->pbAllocVA, 0, MEM_RELEASE);
					pTramStruct->pbAllocVA = NULL;
					pTramStruct->bTramOpt = TRAM_SELF_RECOVER;
					// RIP RELOCATION에 실패한 경우 SELF_RECOVER 방식으로 변경
				}
				else {
					MemoryBarrier();
					FlushInstructionCache(GetCurrentProcess(), pTramStruct->pbAllocVA, bAllocSize);
				}
			}
#else
			BYTE NearJmpX86[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
			//  x86 Near-Relative Jump (JMP rel32(XX XX XX XX) = 0xE9 XX XX XX XX)
			pTramStruct->pbAllocVA = VirtualAllocProbing((PBYTE)pTramStruct->pOrgVA, 0x7FFFFFFF, (pTramStruct->bShellCodeSize + sizeof(NearJmpX86)));
			if (pTramStruct->pbAllocVA != NULL) {
				DWORD dwOrgNextOffset = (DWORD)pTramStruct->pOrgVA + (pTramStruct->bShellCodeSize);
				INT32 NearDist = (INT32)(dwOrgNextOffset - ((DWORD)pTramStruct->pbAllocVA + pTramStruct->bShellCodeSize + +sizeof(NearJmpX86)));
				memcpy(&(NearJmpX86[1]), &NearDist, sizeof(INT32));
				memcpy((PVOID)(pTramStruct->pbAllocVA), &(pTramStruct->pbOrgShellCode[0]), pTramStruct->bShellCodeSize);
				memcpy((PVOID)((PBYTE)pTramStruct->pbAllocVA + pTramStruct->bShellCodeSize), &(NearJmpX86[0]), sizeof(NearJmpX86));
			}
#endif
		}
	}
}


NTSTATUS NTAPI ZwQuerySystemInformation_Hook(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength
) {
	if (TlsGetValue(CtxZwQuerySystemInformation.g_dwTlsIndex)) return 0;
	TlsSetValue(CtxZwQuerySystemInformation.g_dwTlsIndex, (LPVOID)1);

	FARPROC OrgFuncCallVA = TramHookWrite(&CtxZwQuerySystemInformation, TRUE, TRUE);
	NTSTATUS res = ((PFZWQUERYSYSTEMINFORMATION)OrgFuncCallVA)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	TramHookWrite(&CtxZwQuerySystemInformation, TRUE, FALSE);

	TlsSetValue(CtxZwQuerySystemInformation.g_dwTlsIndex, NULL);
	return 0xC0000001; // STATUS_UNSUCCESSFUL
} // ZwQuerySystemInformation 후킹


int WINAPI MessageBoxW_Hook(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType) {

	if (TlsGetValue(CtxMessageBoxW.g_dwTlsIndex)) return 0;
	TlsSetValue(CtxMessageBoxW.g_dwTlsIndex, (LPVOID)1);

	FARPROC OrgFuncCallVA = TramHookWrite(&CtxMessageBoxW, TRUE, TRUE);
	if (((PFMESSAGEBOXW)OrgFuncCallVA)(NULL,
		L"This MessageBoxW API was intercepted by Trampline Hook\nDo you want to see the actual message?\n",
		L"Trampline Hook",
		MB_YESNO | MB_ICONQUESTION) == IDYES) {
		((PFMESSAGEBOXW)OrgFuncCallVA)(hWnd, lpText, lpCaption, uType);
	}
	TramHookWrite(&CtxMessageBoxW, TRUE, FALSE);

	TlsSetValue(CtxMessageBoxW.g_dwTlsIndex, NULL);
	return IDNO;
} // MessageBoxW 후킹


int WINAPI MessageBoxA_Hook(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType) {

	if (TlsGetValue(CtxMessageBoxA.g_dwTlsIndex)) return 0;
	TlsSetValue(CtxMessageBoxA.g_dwTlsIndex, (LPVOID)1);

	FARPROC OrgFuncCallVA = TramHookWrite(&CtxMessageBoxA, TRUE, TRUE);
	if (((PFMESSAGEBOXA)OrgFuncCallVA)(NULL,
		"This MessageBoxA API was intercepted by Trampline Hook\nDo you want to see the actual message?\n",
		"Trampline Hook",
		MB_YESNO | MB_ICONQUESTION) == IDYES) {
		((PFMESSAGEBOXA)OrgFuncCallVA)(hWnd, lpText, lpCaption, uType);
	}
	TramHookWrite(&CtxMessageBoxA, TRUE, FALSE);

	TlsSetValue(CtxMessageBoxA.g_dwTlsIndex, NULL);
	return IDNO;
} // MessageBoxA 후킹


void AdjustInstructionBoundaries(void* pAddr, PBYTE pbShellCode, PBYTE pbShellCodeSize) {
	PBYTE pbAddrPtr = (PBYTE)pAddr;
	BYTE SumSize = 0;

	while (SumSize < *pbShellCodeSize) {
#ifdef _WIN64
		hde64s hs;
		hde64_disasm(pbAddrPtr, &hs);
#else
		hde32s hs;
		hde32_disasm(pbAddrPtr, &hs);
#endif

		pbAddrPtr += hs.len;
		SumSize += hs.len;
	} // 셸코드 길이에 맞는 명령어 경계 길이를 찾음

	if (SumSize > *pbShellCodeSize) {
		memset(pbShellCode + *pbShellCodeSize, 0x90, (size_t)(SumSize - *pbShellCodeSize));
	} // 남은 공간을 NOP(0x90)로 보정해줌

	*pbShellCodeSize = SumSize;
}


BOOL TramHookInit(TramStruct* pTramStruct, LPCWSTR pszDllName, LPCSTR pszFnName, DWORD_PTR dwFnHook, BYTE bHookOpt, BYTE bTramOpt) {
	HMODULE hMod;
	hMod = GetModuleHandle(pszDllName);
	if (hMod == NULL) hMod = LoadLibrary(pszDllName);
	if (hMod == NULL) return FALSE;

	pTramStruct->pOrgVA = GetProcAddress(hMod, pszFnName);
	if (pTramStruct->pOrgVA == NULL) return FALSE;
	// 원본 함수 VA 기록

	pTramStruct->bHookOpt = bHookOpt;
	pTramStruct->bTramOpt = bTramOpt;
	// 후킹 옵션 기록

	pTramStruct->g_dwTlsIndex = TlsAlloc();
	// TlsIndex 할당

	ZeroMemory(&(pTramStruct->pbOrgShellCode[0]), MAX_SC);
	ZeroMemory(&(pTramStruct->pbModShellCode[0]), MAX_SC);
	pTramStruct->pbAllocVA = NULL;
	// 셸코드 공간 초기화

#ifdef _WIN64
	if (HOOK_OPT_MARKER > bHookOpt) return FALSE;
#else
	if (HOOK_OPT_MARKER < bHookOpt) return FALSE;
#endif // 인자 값 착오 방지

	BYTE NearJmpX86 = 0xE9; // x86 Near-Relative Jump (JMP rel32(XX XX XX XX) = 0xE9 XX XX XX XX)
	switch (bHookOpt) {
	case X86_7BYTE: {
		BYTE MsHotPatchCode[7] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x8B, 0xFF }; // (NOP*5), (MOV EDI, EDI)
		BYTE MsDbgHotPatchCode[7] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xFF }; // (INT3*5), (MOV EDI, EDI)
		if ((!memcmp((PBYTE)(pTramStruct->pOrgVA) - 5, MsHotPatchCode, sizeof(MsHotPatchCode))) ||
			(!memcmp((PBYTE)(pTramStruct->pOrgVA) - 5, MsDbgHotPatchCode, sizeof(MsDbgHotPatchCode)))) {
			printf("\t[HOOK] %s\tX86_7BYTE Hooking Tried...\n", pszFnName);
			BYTE SrtJmpX86[2] = { 0xEB, 0xF9 }; // x86 Short Jump (JMP SHORT EIP-5)
			INT32 NearDist = (INT32)(dwFnHook - (DWORD_PTR)pTramStruct->pOrgVA);
			// Short Jump로 인해 EIP가 Near JMP가 실행되는 위치에 맞게끔 이동한다.
			memcpy(&(pTramStruct->pbModShellCode[0]), &NearJmpX86, sizeof(NearJmpX86));
			memcpy(&(pTramStruct->pbModShellCode[1]), &NearDist, sizeof(INT32));
			memcpy(&(pTramStruct->pbModShellCode[5]), &SrtJmpX86, sizeof(SrtJmpX86));
			pTramStruct->bShellCodeSize = 7;
			pTramStruct->pOrgVA = (FARPROC)((PBYTE)pTramStruct->pOrgVA - 5);
			// 7바이트 패치를 위해 오프셋을 5바이트 뒤로 옮긴다.
			break;
		}
		printf("\t[HOOK] %s\tX86_7BYTE Hooking Failed...\n", pszFnName);
		pTramStruct->bHookOpt = X86_5BYTE;
		// break를 없애서 X86_7BYTE를 할 수 없는 경우 X86_5BYTE 패치하도록 한다.
	}

	case X86_5BYTE: {
		printf("\t[HOOK] %s\tX86_5BYTE Hooking Tried...\n", pszFnName);
		INT32 NearDist = (INT32)(dwFnHook - (DWORD_PTR)pTramStruct->pOrgVA - 5);
		// E9 rel32는 현재 EIP가 아니라, 해당 JMP 명령어의 길이(5바이트)를 더한 다음 명령의 EIP를 기준으로 상대 오프셋을 더해 점프한다.
		// 따라서 JMP 명령어의 길이만큼 빼준다.
		memcpy(&(pTramStruct->pbModShellCode[0]), &NearJmpX86, sizeof(NearJmpX86));
		memcpy(&(pTramStruct->pbModShellCode[1]), &NearDist, sizeof(INT32));
		pTramStruct->bShellCodeSize = 5;
		break;
	}

	case X64_14BYTE_STACK: {
		printf("\t[HOOK] %s\X64_14BYTE_STACK Hooking Tried...\n", pszFnName);
		BYTE StackJmpX64[14] = { 0x68 ,0x88 ,0x77 ,0x66 ,0x55 ,0xC7 ,0x44 ,0x24 ,0x04 ,0x44 ,0x33 ,0x22 ,0x11 ,0xC3 };
		// (PUSH 0x55667788), (MOV DWORD PTR[RSP + 4], 0x11223344), (RET)
		DWORD FnHookLow32 = (DWORD)(dwFnHook & 0xFFFFFFFF); // 하위 4바이트 분리 (0x1122334455667788 -> 0x55667788)
		memcpy(&(StackJmpX64[1]), &FnHookLow32, sizeof(DWORD));
		DWORD FnHookHigh32 = (DWORD)(dwFnHook >> 32); // 상위 4바이트 분리 (0x1122334455667788 -> 0x11223344)
		memcpy(&(StackJmpX64[9]), &FnHookHigh32, sizeof(DWORD));
		memcpy(&(pTramStruct->pbModShellCode[0]), &StackJmpX64, sizeof(StackJmpX64));
		pTramStruct->bShellCodeSize = 14;
		break;
	}

	case X64_12BYTE_REGSTER: {
		printf("\t[HOOK] %s\tX64_12BYTE_REGSTER Hooking Tried...\n", pszFnName);
		BYTE RegsterJmpX64[12] = { 0x48 ,0xB8 ,0x88 ,0x77 ,0x66 ,0x55 ,0x44 ,0x33 ,0x22 ,0x11 ,0xFF ,0xE0 };
		// (MOV RAX, 0x1122334455667788), (JMP RAX)
		memcpy(&(RegsterJmpX64[2]), &dwFnHook, sizeof(DWORD_PTR));
		memcpy(&(pTramStruct->pbModShellCode[0]), &RegsterJmpX64, sizeof(RegsterJmpX64));
		pTramStruct->bShellCodeSize = 12;
		break;
	}

	case X64_14BYTE_RIP: {
		printf("\t[HOOK] %s\X64_14BYTE_RIP Hooking Tried...\n", pszFnName);
		BYTE RipJmpX64[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x88 ,0x77 ,0x66 ,0x55, 0x44 ,0x33 ,0x22 ,0x11 };
		// (JMP QWORD PTR [RIP+0]), (DQ 0x1122334455667788)
		memcpy(&(RipJmpX64[6]), &dwFnHook, sizeof(DWORD_PTR));
		memcpy(&(pTramStruct->pbModShellCode[0]), &RipJmpX64, sizeof(RipJmpX64));
		pTramStruct->bShellCodeSize = 14;
		break;
	}

	default: {
		return FALSE;
		break;
	}
	}

	AdjustInstructionBoundaries((PVOID)(pTramStruct->pOrgVA), &(pTramStruct->pbModShellCode[0]), &(pTramStruct->bShellCodeSize));
	// 명령어 경계에 맞춰 셸코드를 NOP(0x90)로 보간해줌
	memcpy(&(pTramStruct->pbOrgShellCode[0]), (PVOID)pTramStruct->pOrgVA, pTramStruct->bShellCodeSize);
	// 원본 셸코드 백업

	TramHookWrite(pTramStruct, FALSE, FALSE);

	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ){
#ifdef _WIN64
	int HookOpt = X64_14BYTE_RIP;	//	HookOpt = X64_12BYTE_REGSTER, X64_14BYTE_STACK, X64_14BYTE_RIP
# else
	int HookOpt = X86_5BYTE;		//	HookOpt = X86_5BYTE, X86_7BYTE
# endif
	int TramOpt = TRAM_ALLOC;		//	TramOpt = TRAM_SELF_RECOVER, TRAM_ALLOC

    switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			DisableThreadLibraryCalls(hModule);
			TramHookInit(&CtxMessageBoxW, L"USER32.dll", "MessageBoxW", (DWORD_PTR)MessageBoxW_Hook, HookOpt, TramOpt);
			TramHookInit(&CtxMessageBoxA, L"USER32.dll", "MessageBoxA", (DWORD_PTR)MessageBoxA_Hook, HookOpt, TramOpt);
			TramHookInit(&CtxZwQuerySystemInformation, L"ntdll.dll", "ZwQuerySystemInformation", (DWORD_PTR)ZwQuerySystemInformation_Hook, HookOpt, TramOpt);
			break;
		} // EAT 후킹
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH: {
			TramHookWrite(&CtxMessageBoxW, FALSE, TRUE);
			TramHookWrite(&CtxMessageBoxA, FALSE, TRUE);
			TramHookWrite(&CtxZwQuerySystemInformation, FALSE, TRUE);
			break;
		} // EAT 원상 복구
    }
    return TRUE;
}


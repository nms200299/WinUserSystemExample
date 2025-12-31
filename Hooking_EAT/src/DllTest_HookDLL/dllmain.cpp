/*
Title : DLL용 EAT 후킹 테스트
Summary : DLL 인젝션 시, 타겟 프로세스의 EAT를 변조하는지 테스트합니다.
*/

#include "pch.h"
#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <intrin.h>

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
int WINAPI MessageBoxW_Hook(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType) {
	if (((PFMESSAGEBOXW)pOrgMessageBoxW)(NULL,
		L"This MessageBoxW API was intercepted by EAT Hook\nDo you want to see the actual message?\n",
		L"EAT Hook",
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
		"This MessageBoxA API was intercepted by EAT Hook\nDo you want to see the actual message?\n",
		"EAT Hook",
		MB_YESNO | MB_ICONQUESTION) == IDYES) {
		return ((PFMESSAGEBOXA)pOrgMessageBoxA)(hWnd, lpText, lpCaption, uType);
	}
	return IDNO;
} // MessageBoxA 후킹


PBYTE x64CodeCave(PBYTE pLoadBase, PBYTE pMaxSearchRange, PBYTE pJmpStub) {
	BYTE FindPadCnt = 0;
	BYTE FindStubCnt = 0;
	for (; pLoadBase <= pMaxSearchRange; pLoadBase++) {
		if ((FindPadCnt >= 12) || (FindStubCnt >= 12)) break;
		if ((*pLoadBase == 0x00) || (*pLoadBase == 0xCC)) {
			// 0x00(패딩)과 0xCC(MSVC 디버깅용 패딩)을 CodeCave 영역으로 사용한다.
			FindPadCnt++;
		}
		else {
			FindPadCnt = 0;
		}
		if (*pLoadBase == *(pJmpStub + FindStubCnt)) {
			FindStubCnt++;
		}
		else {
			FindStubCnt = 0;
		} // 이전에 설치한 StubCode를 찾으면 재활용
	}
	if ((FindPadCnt >= 12) && (FindStubCnt >= 12)) return NULL;
	// 유효한 Code Cave를 확보하지 못한 경우 NULL 리턴한다.
	pLoadBase = pLoadBase - 12;
	// 탐색을 위해 증가시킨 오프셋만큼 감소한다.
	printf("\tCode Cave area found : %p...\n", pLoadBase);
	return pLoadBase;
}

PBYTE x64VirtualAllocProbing(PBYTE pLoadBase, PBYTE pMinSearchRange, PBYTE pMaxSearchRange, PBYTE pJmpStub, BYTE JmpStubSize) {
	while ((pLoadBase == NULL) && (pMinSearchRange <= pMaxSearchRange)) {
		pLoadBase = (PBYTE)VirtualAlloc(pMinSearchRange, JmpStubSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		pMinSearchRange += JmpStubSize;
	} // pMaxSearchRange 범위 안에서 JmpStubSize 할당 가능한 공간을 탐색한다.
	printf("\tAllocate memory : %p...\n", pLoadBase);
	if (pLoadBase == NULL) return NULL;
	return pLoadBase;
}


PBYTE x64TrampolineSetup(PBYTE pLoadBase, PVOID pTargetAddress, DWORD dwSizeOfImg, DWORD* EatFuncAddr) {
	BYTE JmpStub[12] = { 0x48, 0xB8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xFF, 0xE0 };
	// __asm { MOV rax, Address_8Bytes }
	// __asm { JMP rax }
	memcpy(&(JmpStub[2]), pTargetAddress, sizeof(PVOID));
	// JmpStub에 TargetAddress를 채워넣어 완성한다.

	PBYTE CaveMaxSearchRange = pLoadBase + dwSizeOfImg;
	// EAT에 사용될 CodeCave는 PE 파일에 정의된 SizeOfImage 안에서 탐색한다.
	PBYTE AllocMaxSearchRange = pLoadBase + 0xFFFFFFFF;
	// 메모리 할당 가능 공간을 탐색하기 위해서 RVA(DWORD) 범위 내에서 탐색한다.
	// (EAT의 RVA(DWORD) 제약으로 인해 ImageBase 기준 ±4GB 이내 주소만 사용 가능)

	if (*EatFuncAddr >= dwSizeOfImg) {
		VirtualFree(pLoadBase + (*EatFuncAddr), 0, MEM_RELEASE);
		CaveMaxSearchRange = (PBYTE)EatFuncAddr;
		pLoadBase = NULL;
		// 이미 EAT에 VirtualAllocProbing으로 할당된 메모리는 할당 해제 후, 같은 영역 재할당
	}
	else {
		pLoadBase = x64CodeCave(pLoadBase, CaveMaxSearchRange, JmpStub);
	}// CodeCave 방식으로 메모리 탐색

	if (pLoadBase == NULL) {
		pLoadBase = x64VirtualAllocProbing(pLoadBase, CaveMaxSearchRange, AllocMaxSearchRange, JmpStub, sizeof(JmpStub));
		if (pLoadBase == NULL) return NULL;
	}// RVA 표현 가능한 범위 안에서 가상 메모리 할당 루프돕니다.

	DWORD flOldProtect;
	VirtualProtect(pLoadBase, sizeof(JmpStub), PAGE_READWRITE, &flOldProtect);
	// 해당 메모리 영역에 RW 권한을 부여한다.
	memcpy(pLoadBase, &(JmpStub[0]), sizeof(JmpStub));
	// CodeCave 영역에 JumpStub 작성한다.
	VirtualProtect(pLoadBase, sizeof(JmpStub), PAGE_EXECUTE_READ, &flOldProtect);
	// 해당 메모리 영역에 RX 권한을 부여하여 실행 가능하도록 만든다.

	MemoryBarrier();
	// 메모리 가시성(Store)을 보장한다.
	FlushInstructionCache(GetCurrentProcess(), pLoadBase, sizeof(JmpStub));
	// 수정된 코드가 실행되도록 Instruction Cache를 무효화한다.
	return pLoadBase;
}

VOID x64TrampolineRemove(PBYTE pLoadBase, DWORD dwSizeOfImg, DWORD* EatFuncAddrRVA) {
	PBYTE EatFuncAddrVA = pLoadBase + (*EatFuncAddrRVA);
	BYTE PadStub[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	if (*EatFuncAddrRVA >= dwSizeOfImg) {
		printf("\tRemove JmpStub (Alloc) : %p\n", EatFuncAddrVA);
		VirtualFree(EatFuncAddrVA, 0, MEM_RELEASE);
		// VirtualAllocProbing으로 설치된 JmpStub은 Free한다.
	}
	else {
		DWORD flOldProtect;
		VirtualProtect(EatFuncAddrVA, sizeof(PadStub), PAGE_READWRITE, &flOldProtect);
		// 해당 메모리 영역에 RW 권한을 부여한다.
		printf("\tRemove JmpStub (Cave) : %p\n", EatFuncAddrVA);
		memcpy(EatFuncAddrVA, &(PadStub[0]), sizeof(PadStub));
		// Code Cave로 설치된 JmpStub은 0x00으로 수정한다.
	}
}

DWORD EatHooking(LPCWSTR pszDllName, LPCSTR pszFnName, DWORD_PTR pFnAfter, BOOL bRemoveFlag) {
	HMODULE hMod;
	hMod = GetModuleHandle(pszDllName);
	if (hMod == NULL) hMod = LoadLibrary(pszDllName);
	if (hMod == NULL) return 0;

	PBYTE pAddr = NULL;
	pAddr = (PBYTE)hMod;
	pAddr += ((PIMAGE_DOS_HEADER)pAddr)->e_lfanew;
	// IMAGE_NT_HEADER의 시작 주소로 이동한다.
	// (IMAGE_DOS_HEADER의 e_lfanew 값 4바이트를 더하기 할당)

	DWORD dwRVA;
#ifdef _WIN64
	DWORD dwSizeOfImg = ((PIMAGE_NT_HEADERS64)pAddr)->OptionalHeader.SizeOfImage;
	// CodeCave를 탐색하기 위해 이미지의 최대 크기를 알아낸다.
	dwRVA = ((PIMAGE_NT_HEADERS64)pAddr)->OptionalHeader.DataDirectory[0].VirtualAddress; // PE64 Export Table
#else
	dwRVA = ((PIMAGE_NT_HEADERS32)pAddr)->OptionalHeader.DataDirectory[0].VirtualAddress; // PE64 Export Table
#endif
	// IMAGE_NT_HEADER에 명시된 IED(IMAGE_EXPORT_DIRECTORY) 주소를 구한다.

	PIMAGE_EXPORT_DIRECTORY pExportDir;
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hMod + dwRVA);
	// IED(IMAGE_EXPORT_DIRECTORY)의 VA를 구한다.

	DWORD* NameArr = (DWORD*)((BYTE*)hMod + pExportDir->AddressOfNames);
	WORD* OrdinalArr = (WORD*)((BYTE*)hMod + pExportDir->AddressOfNameOrdinals);
	DWORD* AddrArr = (DWORD*)((BYTE*)hMod + pExportDir->AddressOfFunctions);
	// Export Address, Name, Ordinal Table의 VA를 구한다.

	for (DWORD Idx = 0; Idx < pExportDir->NumberOfNames; Idx++) {
		LPCSTR EatFuncName = (LPCSTR)((BYTE*)hMod + NameArr[Idx]);
		if (memcmp(EatFuncName, pszFnName, strlen(pszFnName) + 1) == 0) {
			WORD EatIdx = OrdinalArr[Idx];
			DWORD* EatFuncAddr = &(AddrArr[EatIdx]);
			DWORD OrgEatFuncVal = (*EatFuncAddr) + (DWORD_PTR)hMod;
			DWORD flOldProtect;
			VirtualProtect(EatFuncAddr, sizeof(DWORD), PAGE_READWRITE, &flOldProtect);
#ifdef _WIN64
			if (bRemoveFlag) {
				x64TrampolineRemove((PBYTE)hMod, dwSizeOfImg, EatFuncAddr);
				// EAT 복원시, 이전에 설치한 Trampoline을 제거한다.
			}
			else {
				pFnAfter = (DWORD_PTR)x64TrampolineSetup((PBYTE)hMod, (PVOID)&pFnAfter, dwSizeOfImg, EatFuncAddr);
				if (pFnAfter == NULL) return 0;
				// EAT는 4바이트 RVA만 저장 가능하므로, 모듈 외부 x64 함수(8바이트)는 Trampoline을 설치한다.
			}
#endif
			InterlockedExchange((volatile long*)EatFuncAddr, (long)(pFnAfter - (DWORD_PTR)hMod)); //*EatFuncAddr = pFnAfter - (DWORD_PTR)hMod;
			// 멀티 스레드 환경을 고려해 원자적 연산으로 EAT를 수정한다.
			VirtualProtect(EatFuncAddr, sizeof(DWORD), flOldProtect, &flOldProtect);
			return OrgEatFuncVal;
			// 이후 EAT 복원을 위해 이전 EAT 값을 반환한다. 
		}
	}
	return 0;
}

DWORD dwOrgEatMessageBoxW = 0;
DWORD dwOrgEatMessageBoxA = 0;


FARPROC OrgFuncBackup(LPCWSTR pszDllName, LPCSTR pszFnName) {
	HMODULE hMod;
	hMod = GetModuleHandle(pszDllName);
	if (!hMod) hMod = LoadLibrary(pszDllName);
	if (!hMod) return NULL;
	FARPROC OrgFuncAddr = GetProcAddress(hMod, pszFnName);
	FreeLibrary(hMod);
	return OrgFuncAddr;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ){
    switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			DisableThreadLibraryCalls(hModule);
			pOrgMessageBoxW = OrgFuncBackup(L"USER32.dll", "MessageBoxW");
			pOrgMessageBoxA = OrgFuncBackup(L"USER32.dll", "MessageBoxA");
			dwOrgEatMessageBoxW = EatHooking(L"USER32.dll", "MessageBoxW", (DWORD_PTR)MessageBoxW_Hook, FALSE);
			dwOrgEatMessageBoxA = EatHooking(L"USER32.dll", "MessageBoxA", (DWORD_PTR)MessageBoxA_Hook, FALSE);
			break;
		} // EAT 후킹
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH: {
			EatHooking(L"USER32.dll", "MessageBoxW", dwOrgEatMessageBoxW, TRUE);
			EatHooking(L"USER32.dll", "MessageBoxA", dwOrgEatMessageBoxA, TRUE);
			break;
		} // EAT 원상 복구
    }
    return TRUE;
}


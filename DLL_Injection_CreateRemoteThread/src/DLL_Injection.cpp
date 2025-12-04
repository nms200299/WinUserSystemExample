#include <tchar.h>
#include <windows.h>

int InjectDll(wchar_t* pszDllPath, DWORD dwPID) {
	HANDLE hProcess;
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
	// 최대 권한, 상속 없음으로 프로세스 핸들을 발급받는다.
		wprintf(L"\t[-] OpenProcess() Fail !\n");
		return -1;
	}
	wprintf(L"\t[+] OpenProcess() Success !\n");

	size_t dwDllPathSize = (size_t)((wcslen(pszDllPath)+1)*sizeof(wchar_t));
	// NULL-Terminate가 고려된 DLL 경로 길이를 구한다.
	LPVOID pThreadParam;
	if (!(pThreadParam = VirtualAllocEx(hProcess, NULL, dwDllPathSize, MEM_COMMIT, PAGE_READWRITE))) {
		// 인젝션할 프로세스에 위 길이만큼 가상 메모리 공간을 할당한다.
		// (생성할 스레드에서 접근할 수 있는 메모리 공간이 필요하기에)
		wprintf(L"\t[-] VirtualAllocEx() Fail !\n");
		return -2;
	}
	wprintf(L"\t[+] VirtualAllocEx() Success !\n");

	if (!(WriteProcessMemory(hProcess, pThreadParam, (LPCVOID)pszDllPath, dwDllPathSize, NULL))) {
		// 위 가상 메모리 공간에 DLL 경로를 대입한다.
		wprintf(L"\t[-] WriteProcessMemory() Fail !\n");
		return -3;
	}
	wprintf(L"\t[+] WriteProcessMemory() Success !\n");

	HMODULE hMod;
	if (!(hMod = GetModuleHandle(L"kernel32.dll"))) {
		wprintf(L"\t[-] GetModuleHandle() Fail !\n");
		return -4;
	} // kernel32.dll 모듈의 핸들을 구합니다.
	// (모든 일반 프로세스는 kernel32.dll을 로드한다)

	LPTHREAD_START_ROUTINE pThreadProc;
	if (!(pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW"))) {
		// kernel32.dll에 존재하는 LoadLibraryW() API 주소를 구합니다.
		// (시스템이 살아 있는 동안 같은 프로세스마다 같은 주소에 DLL이 매핑되는 점을 이용)
		wprintf(L"\t[-] GetProcAddress() Fail !\n");
		return -5;
	}

	HANDLE hThread;
	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pThreadParam, 0, NULL))) {
		wprintf(L"\t[-] CreateRemoteThread() Fail !\n");
		return -6;
	} // LoadLibraryW() API로 DLL을 로드하는 원격 스레드를 생성합니다.

	WaitForSingleObject(hThread, INFINITE);
	// 생성한 원격 스레드가 종료될 때까지 기다립니다.
	
	VirtualFreeEx(hProcess, pThreadParam, 0, MEM_RELEASE);
	// 메모리 누수를 방지하기 위해 할당 해제합니다.

	CloseHandle(hThread);
	CloseHandle(hProcess);
	return 0;
}


void usage() {
	wprintf(L"usage : Injector.exe [DLL PATH] [PID]\n");
	system("pause");
	exit(1);
}

int wmain(int argc, wchar_t* argv[]){
	wprintf(L"[DLL Injection (CreateRemoteThread) Example]\n");

	if (argc != 3) usage();

	wchar_t* DllPath = argv[1];
	DWORD PID = (DWORD)_wtol(argv[2]);
	// TCHAR을 정수로 변환

	if (InjectDll(DllPath, PID) == 0) wprintf(L"\t[*] DLL Injection Success !\n");
	else wprintf(L"\t[*] DLL Injection Fail !\n");

	//system("pause");
	return 0;
}

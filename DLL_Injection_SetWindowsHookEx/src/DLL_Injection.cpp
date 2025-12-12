#include <tchar.h>
#include <windows.h>
#include <process.h>

typedef void (*fnSetLoadThreadInfo)(int pid, int tid);
HHOOK g_hHook = NULL;
HINSTANCE g_hDll = NULL;

unsigned __stdcall InjectDll(void* param) {
	wchar_t* pszDllPath = (wchar_t*)param;
	g_hDll = LoadLibraryW(pszDllPath);
	if (g_hDll == NULL) {
		wprintf(L"\t[-] LoadLibrary Fail !\n");
		return 1;
	}
	wprintf(L"\t[+] LoadLibrary Success !\n");
	// DLL을 로드합니다.

	HOOKPROC procAddr = (HOOKPROC)GetProcAddress(g_hDll, "KeyboardProc");
	if (procAddr == NULL) {
		wprintf(L"\t[-] GetProcAddress(KeyboardProc) Fail !\n");
		FreeLibrary(g_hDll);
		return 2;
	}
	wprintf(L"\t[+] GetProcAddress(KeyboardProc) Success !\n");
	// 키보드 훅 함수 주소를 구합니다. 

	fnSetLoadThreadInfo SetInfo = (fnSetLoadThreadInfo)GetProcAddress(g_hDll, "SetLoadThreadInfo");
	if (procAddr == NULL) {
		wprintf(L"\t[-] GetProcAddress(SetLoadThreadInfo) Fail !\n");
		FreeLibrary(g_hDll);
		return 3;
	}
	wprintf(L"\t[+] GetProcAddress(SetLoadThreadInfo) Success !\n");
	// 로드한 PID, TID를 공유할 함수 주소를 구합니다.
	SetInfo((int)GetCurrentProcessId(), (int)GetCurrentThreadId());
	// 인젝터 PID, 후킹 인젝터 TID를 넘깁니다.

	g_hHook = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)procAddr, g_hDll, 0);
	if (g_hHook == NULL) {
		wprintf(L"\t[-] SetWindowsHookEx Fail !\n");
		FreeLibrary(g_hDll);
		return 4;
	}
	wprintf(L"\t[+] SetWindowsHookEx Success !\n");
	// 전역 후킹 체인에 등록합니다.

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
		// This hook may be called in the context of the thread that installed it.
		// The call is made by sending a message to the thread that installed the hook.
		// Therefore, the thread that installed the hook must have a message loop.
	} // (https://learn.microsoft.com/en-us/windows/win32/winmsg/keyboardproc)

	return 0;
}

void usage() {
	wprintf(L"usage : Injector.exe [DLL PATH]\n");
	system("pause");
	exit(1);
}

int wmain(int argc, wchar_t* argv[]){
	wprintf(L"[Global DLL Injection (CreateRemoteThread) Example]\n");

	wchar_t* DllPath = argv[1];
	unsigned ThreadId = 0;
	HANDLE hThread = NULL;
	hThread = (HANDLE)_beginthreadex(
		NULL,
		0,
		InjectDll,
		(void*)DllPath,
		0,
		&ThreadId
	); // 훅 스레드를 실행합니다.

	if (hThread == 0) {
		wprintf(L"\t[-] HookThread Create Fail !\n");
		return -1;
	} 

	system("pause");
	PostThreadMessage(ThreadId, WM_QUIT, 0, 0);
	// 메시지 루프를 종료하는 메시지를 보냅니다.
	WaitForSingleObject(hThread, INFINITE);
	// 스레드 종료까지 대기합니다.

	if (g_hHook != NULL) {
		UnhookWindowsHookEx(g_hHook);
		g_hHook = NULL;
	}
	if (g_hDll != NULL) {
		FreeLibrary(g_hDll);
		g_hDll = NULL;
	}
	// 전역 훅 체인을 취소합니다.

	DWORD dwExitCode = 0;
	GetExitCodeThread(hThread, &dwExitCode);
	// 스레드의 리턴 값을 받아옵니다.
	CloseHandle(hThread);
	

	if (dwExitCode == 0) wprintf(L"\t[*] Global DLL Injection Success !\n");
	else wprintf(L"\t[*] Global DLL Injection Fail !\n");

	return 0;
}

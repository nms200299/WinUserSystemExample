#include <tchar.h>
#include <windows.h>

int main() {
    _tprintf(L"[Hooking Test Application]\n");
    _tprintf(L"Hello Hooking");
    system("pause");
    return 0;
}

// Windows 10 일부 버전에서 윈도우 내부 프로그램에 대한 후킹이 먹히지 않아 따로 테스트 프로그램을 제작함.
// 해당 이슈는 보호 정책(CFG, )과는 무관하며, Windows 10 22H2 19045.2965에서 발생함.

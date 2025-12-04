/*
Title : IAT 후킹 타겟 프로그램
Summary : 테스트를 위해 DLL 인젝션 당할 프로그램입니다.
*/

#include <windows.h>
#include <stdio.h>

void test() {
	MessageBoxW(NULL, L"TEST", L"TEST", MB_OK | MB_ICONASTERISK);
	MessageBoxA(NULL, "TEST", "TEST", MB_OK | MB_ICONASTERISK);
	system("pause");
}

int main() {
	printf("[IAT 후킹 테스트]\n");
	printf("IAT 후킹 전\n");
	test(); // IAT 후킹 전 테스트
	printf("IAT 후킹 후\n");
	test(); // IAT 후킹 후 테스트
} // 테스트용 프로그램 (MessageBoxW/A 구분)
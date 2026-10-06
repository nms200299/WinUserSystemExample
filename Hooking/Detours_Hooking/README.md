# Detours Detours 라이브러리를 이용한 API 후킹

* 작성자 : 2N(nms200299)
* 블로그 포스팅 (개념 정리) :

  * 

### 시연 영상 :


### 구현 내용 :

* Detours 라이브러라를 활용하여 MessageBoxW/A(), ZwQuerySystemInformation() 후킹 구현

  * AllInOne.exe : 프로그램 내에서 자기 자신 대상으로 후킹 전후 테스트

  * DLLTest_HookDLL.dll : DLL 인젝션될 DLL

  * DLLTest_TestProgram.exe : DLL 인젝션 대상 프로그램으로 후킹 전후 테스트

### 테스트 결과 :

| OS 종류 | OS 아키텍처 | x86 Detours 후킹 | x64 Detours 후킹 |
|---|---|:---:|:---:|
| Windows 7 | x86 | O | - |
| Windows 7 | x64 (WoW64) | O | O |
| Windows 8.1 | x86 | O | - |
| Windows 8.1 | x64 (WoW64) | O | O |
| Windows 10 | x86 | O | - |
| Windows 10 | x64 (WoW64) | O | O |
| Windows 11 | x64 (WoW64) | O | O |
#### 표기 기준

* O : 정상 동작
* \- : 구조적으로 미지원

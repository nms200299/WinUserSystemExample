# SetWindowsHookEx를 이용한 Global DLL Injection

* 작성자 : 2N(nms200299)

* 블로그 포스팅 :

  * https://blog.naver.com/nms200299/224107869569

* 시연 영상 :

https://github.com/user-attachments/assets/ce340783-f8ef-450c-a0d9-f409669a413d

* 테스트 결과 :

|OS 종류|OS 아키텍처|PE 아키텍처|DLL 인젝션 결과|
|---|---|---|---|
|Windows 7|x86|x86|O|
||x64|x64|O|
|||x86 (WoW64)|O|
|Windows 8.1|x86|x86|O|
||x64|x64|O|
|||x86 (WoW64)|O|
|Windows 10|x86|x86|O|
||x64|x64|O|
|||x86 (WoW64)|O|
|Windows 11|x64|x64|O|
|||x86 (WoW64)|O|

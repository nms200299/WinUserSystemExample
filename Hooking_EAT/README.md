# EAT 후킹을 이용한 API 후킹

* 작성자 : 2N(nms200299)
* 블로그 포스팅 (개념 정리) :

  * https://blog.naver.com/nms200299/224129850433

### 시연 영상 :

https://github.com/user-attachments/assets/e0928dbb-5804-4aa7-b2df-6c11648fb1fd

### 구현 내용 :

* x86 EAT 후킹

* x64 EAT 후킹

  * CodeCave 할당 기법

  * Allocation Probing 할당 기법


### 테스트 결과 :

| OS 종류 | OS 아키텍처 | x86 EAT 후킹 | x64 EAT 후킹 (CodeCave) | x64 EAT 후킹 (Allocation Probing) |
|--------|-------------|--------------|-------------------|-----------------------------|
| Windows 7 | x86 | O | - | - |
|| x64 (WoW64) | O | O | O |
| Windows 8.1 (Update 3) | x86 | O | - | - |
|| x64 (WoW64) | O | O | O |
| Windows 10 | x86 | O | - | - |
|| x64 (WoW64) | O | △ (CFG) | O |
| Windows 11 | x64 (WoW64) | O | △ (CFG) | O |

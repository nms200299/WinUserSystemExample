# Trampoline 후킹을 이용한 API 후킹

* 작성자 : 2N(nms200299)
* 블로그 포스팅 (개념 정리) :

  * https://blog.naver.com/nms200299/224154215713

### 시연 영상 :



https://github.com/user-attachments/assets/557ae6e1-c463-47cc-8acf-72eb841a7dba





### 구현 내용 :

|구현 항목|아키텍처|구현 내용|비고|
|-|-|-|-|
|**후킹 전략**|x86|- EIP-relative Jump (5byte Patch)<br>- HotPatch 기반 2-stage Jump (7byte)|옵션화 (선택 가능)|
||x64|- RET-based Control Transfer (14byte)<br>- Register-Indirect Jump (12byte)<br>- RIP-relative-Indirect Jump (14byte)|옵션화 (선택 가능)|
|**트램펄린 전략**|공통|- Self-Restoring 기반 Inline Hook<br>- Multi-stage 기반 Trampoline Hook<br>- ±2GB 범위 내 트램펄린 공간 할당|옵션화 (선택 가능)|
|**명령어 경계**|공통|- HDE32 / HDE64 라이브러리 사용<br>- 명령어 단위 분석 후 NOP 보간 처리||
|**RIP 재계산**|x64|- RIP + disp32 기반 주소 재계산 로직 구현||
|**동시성 문제**|공통|- TLS Flag를 이용한 재진입 방지<br>- SpinLock 기반 레이스 컨디션 방지<br>- Memory Barrier 적용<br>- I-Cache 무효화 처리||
|**테스트 코드**|공통|- Implicit / Explicit API 후킹·언후킹 테스트<br>- 대상 API: `MessageBoxW/A`, `ZwQuerySystemInformation`||

### 테스트 결과 :

|OS 종류|OS 아키텍처|EIP-relative (5byte)|HotPatch (7byte)|RET Base (14byte)|Register Base (12byte)|RIP-relative (14byte)|
|-|-|-|-|-|-|-|
|**Windows 7**|x86|O|O|-|-|-|
||x64 (WoW64)|O|O|O|O|O|
|**Windows 8.1**<br>(Update 3)|x86|O|△ (CFG, U3)|-|-|-|
||x64 (WoW64)|O|△ (CFG, U3)|O|O|O|
|**Windows 10**|x86|O|△ (CFG)|-|-|-|
||x64 (WoW64)|O|△ (CFG)|△ (CET, 유추)|O|O|
|**Windows 11**|x64 (WoW64)|O|△ (CFG)|△ (CET)|O|O|

#### 표기 기준

* O : 정상 동작
* △ : 보안 기법(CFG, CET 등)으로 인해 제한적 또는 우회 필요
* 

  * : 구조적으로 미지원

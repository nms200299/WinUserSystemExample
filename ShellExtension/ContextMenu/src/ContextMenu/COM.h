#pragma once
#include "pch.h"
#include "framework.h"
#include "resource.h"

#include <shlobj.h> // Windows Shell
#include <windows.h> // COM / Windows
#include "ContextMenu_i.h" // GUID / CLSID가 선언된 헤더
#include <vector>
#include <string>
using namespace ATL;

class ATL_NO_VTABLE CMyContextMenu :
    public CComObjectRootEx<CComSingleThreadModel>,
    public CComCoClass<CMyContextMenu, &CLSID_MyContextMenu>,
    public IShellExtInit, // Shell Extension 초기화 인터페이스
    public IContextMenu // Context Menu 인터페이스
{
public:
    CMyContextMenu() {}
    ~CMyContextMenu() {
        if (m_hBitmap) {
            DeleteObject(m_hBitmap);
            m_hBitmap = NULL;
        }
    } // 소멸자에서 m_hBitmap 오브젝트 할당 해제

    DECLARE_REGISTRY_RESOURCEID(IDR_CONTEXTMENU)
    // rgs 리소스 등록

    BEGIN_COM_MAP(CMyContextMenu)
        COM_INTERFACE_ENTRY(IShellExtInit)
        COM_INTERFACE_ENTRY(IContextMenu)
    END_COM_MAP()
    // COM 인터페이스 등록

    /* IShellExtInit 인터페이스 가상함수 오버라이드 */
    STDMETHOD(Initialize)(        
        PCIDLIST_ABSOLUTE pidlFolder,
        IDataObject* pDataObj,
        HKEY hProgID);
    // 파일/폴더 경로 처리

    /* IContextMenu 인터페이스 가상함수 오버라이드 */
    STDMETHOD(QueryContextMenu)(
        HMENU hMenu,
        UINT indexMenu,
        UINT idCmdFirst,
        UINT idCmdLast,
        UINT uFlags);
    // 메뉴 출력 처리
    STDMETHOD(InvokeCommand)(
        LPCMINVOKECOMMANDINFO pCmdInfo);
    // 메뉴 클릭 처리
    STDMETHOD(GetCommandString)(
        UINT_PTR idCmd,
        UINT uType,
        UINT* pReserved,
        LPSTR pszName,
        UINT cchMax);
    // 메뉴 도움말 처리

    /* 사용자 정의 함수 및 멤버 변수 */
    HBITMAP CMyContextMenu::IconToBitmap(HICON hIcon, int cx, int cy);
    // 아이콘 객체를 비트맵 객체로 변환
    HBITMAP m_hBitmap = NULL;
    // 메뉴의 아이콘을 표시할 비트맵 객체
    std::vector<std::wstring> m_arSelectFile;
    // 선택된 경로 항목을 담을 벡터
};

OBJECT_ENTRY_AUTO(__uuidof(MyContextMenu), CMyContextMenu)
// ATL COM 객체를 COM Class Factory에 등록
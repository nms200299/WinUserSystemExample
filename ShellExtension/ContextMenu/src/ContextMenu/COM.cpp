#include "pch.h"
#include "COM.h"

/* IShellExtInit::Initialize 구현
    (파일/폴더 경로 처리) */
HRESULT CMyContextMenu::Initialize(
    LPCITEMIDLIST pidlFolder,
    LPDATAOBJECT pDataObj,
    HKEY hProgID)
{
    FORMATETC fmt = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    // CF_HDROP 형식의 데이터를 요청하기 위한 구조체
    STGMEDIUM stg = { TYMED_HGLOBAL };
    // 전달받을 데이터를 저장할 구조체
    HDROP     hDrop;
    // CF_HDROP 데이터가 저장될 HDROP 핸들

    if (FAILED(pDataObj->GetData(&fmt, &stg))){
        return E_INVALIDARG;
    } // CF_HDROP 데이터를 가져오지 못한 경우 오류 반환

    hDrop = (HDROP)GlobalLock(stg.hGlobal);
    // STGMEDIUM에 저장된 HGLOBAL 메모리를 잠그고 실제 HDROP 데이터에 접근

    if (hDrop == NULL){
        return E_INVALIDARG;
    } // HDROP 데이터에 접근하지 못한 경우 오류 반환

    UINT uNumFiles = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);
    // HDROP에 포함된 전체 파일/폴더 개수를 조회

    if (uNumFiles == 0){
        GlobalUnlock(stg.hGlobal);
        ReleaseStgMedium(&stg);
        return E_INVALIDARG;
    } // 선택된 폴더/파일이 없는 경우, 메모리 해제 후 오류 반환

    HRESULT hr = S_OK;
    for (UINT uFileIdx = 0; uFileIdx < uNumFiles; uFileIdx++){
        UINT cchFile = DragQueryFile(hDrop, uFileIdx, NULL, 0);
        if (cchFile == 0) continue;
        // 선택된 폴더/파일의 길이 조회

        std::wstring filePath(static_cast<std::wstring::size_type>(cchFile) + 1, L'\0');
        // 파일 경로를 저장할 std::wstring 버퍼 생성
        DragQueryFile(hDrop, uFileIdx, &filePath[0], cchFile + 1);
        // 파일 경로를 버퍼에 저장

        filePath.resize(cchFile);
        // 실제 경로 길이에 맞게 정리
        m_arSelectFile.push_back(filePath);
        // 멤버 변수 벡터에 파일/폴더 경로 추가
    }

    GlobalUnlock(stg.hGlobal); // 잠근 HGLOBAL 메모리 해제
    ReleaseStgMedium(&stg); // STGMEDIUM 리소스 해제
    return hr;
}


/* IContextMenu::QueryContextMenu 구현
    (메뉴 출력 처리) */
HRESULT CMyContextMenu::QueryContextMenu(
    HMENU hMenu,
    UINT  uMenuIndex,
    UINT  uidFirstCmd,
    UINT  uidLastCmd,
    UINT  uFlags)
{
    if (uFlags & CMF_DEFAULTONLY) {
        return MAKE_HRESULT ( SEVERITY_SUCCESS, FACILITY_NULL, 0 );
    } // CMF_DEFAULTONLY 플래그가 설정된 경우,
    // 기본 명령만 요청한 것이므로 사용자 정의 메뉴를 추가하지 않음

    HMENU hNewMenu = CreatePopupMenu();
    if (!hNewMenu) return E_OUTOFMEMORY;
    // 새로운 Popup Menu 생성

    UINT idCmd = uidFirstCmd; // Shell에서 할당한 첫 번째 Command부터 사용
    AppendMenu(hNewMenu, MF_STRING, idCmd++, _T("서브 메뉴 1 (경로 출력)"));
    AppendMenu(hNewMenu, MF_STRING, idCmd++, _T("서브 메뉴 2 (테스트 메시지 박스)"));
    // Popup Menu에 각 서브 메뉴 추가
    InsertMenu(hMenu, uMenuIndex, MF_BYPOSITION | MF_POPUP, (UINT_PTR)hNewMenu, _T("메인 메뉴") );
    // 생성한 Popup Menu를 Context Menu에 추가

    HINSTANCE hInst = _AtlBaseModule.GetModuleInstance();
    HICON hIcon = (HICON)LoadImage(
        _AtlBaseModule.GetModuleInstance(),
        MAKEINTRESOURCE(IDB_MY_ICON),
        IMAGE_ICON,
        16,
        16,
        LR_DEFAULTCOLOR);
    // 리소스에 있는 아이콘 객체를 로드

    if (hIcon) {
        m_hBitmap = IconToBitmap(hIcon, 16, 16);
        DestroyIcon(hIcon);
        // 아이콘 객체를 비트맵 객체로 변환한 후 아이콘 객체 해제
        if (m_hBitmap) {
            MENUITEMINFO mii = {};
            mii.cbSize = sizeof(MENUITEMINFO);
            mii.fMask = MIIM_BITMAP;
            mii.hbmpItem = m_hBitmap;
            SetMenuItemInfo(hMenu, uMenuIndex, TRUE, &mii);
        } // 해당 비트맵 객체를 Popup Menu 위치에 적용
    }

    return MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, idCmd - uidFirstCmd);
    // 사용한 CommandID 개수를 담아서 리턴
}


/* 아이콘 -> 비트맵 변환 함수 */
HBITMAP CMyContextMenu::IconToBitmap(HICON hIcon, int cx, int cy){
    void* pBits = NULL;
    HDC hdcScreen = GetDC(NULL);
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = cx; // 비트맵 가로 크기
    bi.bmiHeader.biHeight = -cy; // 비트맵 세로 크기 (top-down)
    bi.bmiHeader.biPlanes = 1; // 비트맵 Plane 
    bi.bmiHeader.biBitCount = 32; // BGRA (32bit)
    bi.bmiHeader.biCompression = BI_RGB; // 압축 미지정
    HBITMAP hBitmap = CreateDIBSection(hdcScreen, &bi, DIB_RGB_COLORS, &pBits, NULL, 0);
    // RGB 색상을 사용하는 비트맵 객체 생성

    if (hBitmap) {
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        HGDIOBJ hOld = SelectObject(hdcMem, hBitmap);
        SIZE_T bitmapSize = static_cast<SIZE_T>(cx) * static_cast<SIZE_T>(cy) * 4;
        ZeroMemory(pBits, bitmapSize);
        // 전체 픽셀 * 4Byte (32bit)
        DrawIconEx(hdcMem, 0, 0, hIcon, cx, cy, 0, NULL, DI_NORMAL);
        // 비트맵에 아이콘을 그림
        SelectObject(hdcMem, hOld);
        DeleteDC(hdcMem);
    }
    ReleaseDC(NULL, hdcScreen);
    return hBitmap;
}


/* IContextMenu::InvokeCommand 구현
    (목록 클릭 기능) */
HRESULT CMyContextMenu::InvokeCommand (LPCMINVOKECOMMANDINFO pCmdInfo){
    if (HIWORD(pCmdInfo->lpVerb != 0))
        return E_INVALIDARG;
    // lpVerb가 문자열 형태면 처리하지 않음

    switch (LOWORD(pCmdInfo->lpVerb)) {
    // 선택한 Command Id의 인덱스 
        case 0: {
            for (const auto& file : m_arSelectFile){
                MessageBox(pCmdInfo->hwnd, file.c_str(), _T("서브 메뉴 1"), MB_ICONINFORMATION);
            }       
            return S_OK;
        } // 서브 메뉴 1일 때, 각 선택된 파일/폴더 목록을 메시지 박스로 출력함

        case 1: {
            MessageBox ( pCmdInfo->hwnd, _T("테스트 메시지"), _T("서브 메뉴 2"), MB_ICONINFORMATION );
            return S_OK;
        } // 서브 메뉴 2일 때, 테스트 메시지 박스를 출력함
    }
    return E_INVALIDARG;
}


/* IContextMenu::GetCommandString 구현
    (메뉴 도움말 처리, Win10/11 안 먹힘) */
HRESULT CMyContextMenu::GetCommandString(
    UINT_PTR idCmd,
    UINT uFlags,
    UINT* pwReserved,
    LPSTR pszName,
    UINT cchMax)
{
    if (0 != idCmd) return E_INVALIDARG;
    if (uFlags & GCS_HELPTEXT) {
        if (uFlags & GCS_UNICODE) {
            // 유니코드 사용 시,
            const wchar_t* szText = L"마우스를 가져다 댔을 때 상태창에 뜨는 문자열";
            if (!lstrcpynW((LPWSTR)pszName, szText, cchMax)) return E_FAIL;
        } else {
            // ANSI 사용 시,
            const wchar_t* szText = L"마우스를 가져다 댔을 때 상태창에 뜨는 문자열";
            WideCharToMultiByte(CP_ACP, 0, szText, -1, pszName, cchMax, NULL, NULL);
        }
        return S_OK;
    }
    return E_INVALIDARG;
}
// dllmain.h : 모듈 클래스의 선언입니다.

class CContextMenuModule : public ATL::CAtlDllModuleT< CContextMenuModule >
{
public :
	DECLARE_LIBID(LIBID_ContextMenuLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_CONTEXTMENU, "{e6a63ec6-47f3-4245-947b-8fca7d42b357}")
};

extern class CContextMenuModule _AtlModule;

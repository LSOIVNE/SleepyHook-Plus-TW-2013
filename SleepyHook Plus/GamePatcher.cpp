#include <Windows.h>
#include "Main.h"
#include "MetaHook.h"
#include "Utils.h"

unsigned long m_iHostIPAddress;
unsigned short m_iHostPort;

void WriteBytes(PVOID address, void* val, int bytes) 
{
	DWORD d, ds;
	VirtualProtect(address, bytes, PAGE_EXECUTE_READWRITE, &d);
	memcpy(address, val, bytes);
	VirtualProtect(address, bytes, d, &ds);
}

bool SetIMEEnabled(HWND hwnd_, bool enabled)
{
	HIMC himc = ImmGetContext(hwnd_);
	if (!himc)
		return false;
	BOOL current = ImmGetOpenStatus(himc);
	if (current == (enabled ? TRUE : FALSE))
	{
		ImmReleaseContext(hwnd_, himc);
		return true;
	}
	BOOL ok = ImmSetOpenStatus(himc, enabled ? TRUE : FALSE);
	ImmReleaseContext(hwnd_, himc);
	return ok == TRUE;
}

namespace RankLocationFix
{
	unsigned int(__thiscall* oRankSetPlayerInfo)(void* thisptr, int a2);
	void RefreshDisplay(void* thisptr)
	{
		// (sub_372FFB10 > LABEL_27)
		DWORD pBegin = *(DWORD*)((char*)thisptr + 0x410);
		DWORD pEnd = *(DWORD*)((char*)thisptr + 0x414);
		for (DWORD ptr = pBegin; ptr < pEnd; ptr += 4)
		{
			DWORD observer = *(DWORD*)ptr;
			if (observer)
			{
				DWORD vtable = *(DWORD*)observer;
				reinterpret_cast<void(__thiscall*)(void*)>(*(DWORD*)(vtable + 0x10))((void*)observer);
			}
		}
	}

	unsigned int __fastcall RankSetPlayerInfo(void* thisptr, void* edx, int a2)
	{
		int regionType = *(int*)((char*)a2 + 0x20);

		// 顯示地區為1的時候不處理，1為只顯示城市
		if (regionType != 2 && regionType != 3)
			return oRankSetPlayerInfo(thisptr, a2);

		unsigned int packed = *(unsigned int*)((char*)a2 + 0x24);
		// cstrike_tw/resource/location.csv
		unsigned int city = 0, district = 0, village = 0;

		if (regionType == 2)
		{
			// 端口發包格式：(縣市 << 10) | 鄉鎮區
			district = packed & 0x3FF;
			city = (packed >> 10) & 0xFF;
		}
		else
		{
			// 端口發包格式：(縣市 << 24) | (鄉鎮區 << 14) | 村里
			village = packed & 0x3FFF;
			district = (packed >> 14) & 0x3FF;
			city = (packed >> 24) & 0xFF;
		}

		*(int*)((char*)a2 + 0x20) = 1; // 將類別改為1，避免觸發壞掉的type 2/3
		*(unsigned int*)((char*)a2 + 0x24) = city;

		// 暫時清空vector，讓原函式內部的UI刷新迴圈跑空 (sub_372FFB10 > LABEL_27)
		DWORD* pBegin = (DWORD*)((char*)thisptr + 0x410);
		DWORD* pEnd = (DWORD*)((char*)thisptr + 0x414);
		DWORD savedEnd = *pEnd;
		*pEnd = *pBegin;

		auto ret = oRankSetPlayerInfo(thisptr, a2);

		// 還原vector
		*pEnd = savedEnd;

		// 補上鄉鎮區與村里 Index
		*(DWORD*)((char*)thisptr + 0x3D8) = district;
		*(DWORD*)((char*)thisptr + 0x3DC) = village;

		RefreshDisplay(thisptr);
		return ret;
	}
}

namespace HackShield
{
	void(__cdecl* oSetACInit)();
	void SetACInit()
	{

	}

	void(__cdecl* oHook1)();
	void Hook1()
	{

	}

	bool(__cdecl* oHook2)();
	bool Hook2()
	{
		oHook2();
		return 1;
	}
}

namespace CSONMWrapper
{
	std::string m_sLastSubmitAccount;
	std::string m_sLastSubmitPassword;
	char(__thiscall* oCSONMWrapper__AuthUser)(void* thisptr, const char* szAccount, const char* szPassword, int a4);
	char __fastcall AuthUser(void* thisptr, void* edx, const char* szAccount, const char* szPassword, int a4)
	{
		m_sLastSubmitAccount = szAccount;
		m_sLastSubmitPassword = szPassword;
		return 1;
	}

	bool(__cdecl* oCheckIsAge18)();
	bool __cdecl CheckIsAge18()
	{
		return 1;
	}

	void(__stdcall* oCOutPacket__SendLoginPacket)(DWORD** account, DWORD** password);
	void __stdcall COutPacket__SendLoginPacket(DWORD** account, DWORD** password)
	{
		//NMCO Bypass後的問題 會導致登入包的帳密被破壞
		DWORD dwAccountTable = (DWORD)*account;
		DWORD dwPasswordTable = (DWORD)*password;

		*(DWORD*)(dwAccountTable - 0xC) = m_sLastSubmitAccount.length();
		memcpy((void*)dwAccountTable, m_sLastSubmitAccount.c_str(), m_sLastSubmitAccount.length());
		memcpy((void*)(dwAccountTable + m_sLastSubmitAccount.length()), "\0", 1);

		*(DWORD*)(dwPasswordTable - 0xC) = m_sLastSubmitPassword.length();
		memcpy((void*)dwPasswordTable, m_sLastSubmitPassword.c_str(), m_sLastSubmitPassword.length());
		memcpy((void*)(dwPasswordTable + m_sLastSubmitPassword.length()), "\0", 1);
		oCOutPacket__SendLoginPacket(account, password);

		m_sLastSubmitAccount.clear();
		m_sLastSubmitPassword.clear();
	}
}

namespace HookFuncs
{
	char m_iEnableSSL = 1;
	int(__cdecl* oSocketManager__Constructor)(char* a1, char a2);
	int __cdecl SocketManager__Constructor(char* a1, char a2)
	{
		return oSocketManager__Constructor(a1, m_iEnableSSL);
	}

	int(__thiscall* oIpRedirector)(void* pThis, int ip, __int16 port, char a4);
	int __fastcall IpRedirector(void* pThis, void* edx, int ip, __int16 port, char a4)
	{
		return oIpRedirector(pThis, m_iHostIPAddress, m_iHostPort, a4);
	}

	int(__cdecl* oHolePunchFuncSetServerInfo)(int ip, __int16 port);
	int __cdecl HolePunchFuncSetServerInfo(int ip, __int16 port)
	{
		return oHolePunchFuncSetServerInfo(m_iHostIPAddress, m_iHostPort);
	}

	static bool m_bWasChatting = false;
	static bool m_bIMEDisabled = false;
	static bool m_bWasInGame = false;
	LRESULT(__thiscall* oCGame__WndProc)(void* thisptr, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
	LRESULT __fastcall CGame__WndProc(void* thisptr, void* edx, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
	{
		bool bCursorShowAndInChatInput = *(bool*)(0x375B6E81 + 0x01);
		bool bInGame = *(int*)(0x38F7F8A0) >= 5;

		if (bInGame && !bCursorShowAndInChatInput)
		{
			switch (Msg)
			{
			case WM_IME_STARTCOMPOSITION:
			case WM_IME_ENDCOMPOSITION:
			case WM_IME_COMPOSITION:
			case WM_IME_SETCONTEXT:
				return 0;
			}
		}

		LRESULT ret = oCGame__WndProc(thisptr, hWnd, Msg, wParam, lParam);

		if (Msg == WM_ACTIVATEAPP && !wParam)
			m_bIMEDisabled = false;

		if (bInGame && !m_bWasInGame)
			m_bIMEDisabled = false;

		m_bWasInGame = bInGame;

		if (bCursorShowAndInChatInput && !m_bWasChatting)
		{
			SetIMEEnabled(hWnd, true);
			m_bIMEDisabled = false;
		}

		if (!bCursorShowAndInChatInput && m_bWasChatting && bInGame)
		{
			SetIMEEnabled(hWnd, false);
			m_bIMEDisabled = true;
		}

		m_bWasChatting = bCursorShowAndInChatInput;

		if (bInGame && !bCursorShowAndInChatInput)
		{
			switch (Msg)
			{
			case WM_ACTIVATEAPP:
				if (wParam)
				{
					SetIMEEnabled(hWnd, false);
					m_bIMEDisabled = true;
				}
				break;
			case WM_INPUTLANGCHANGE:
				SetIMEEnabled(hWnd, false);
				m_bIMEDisabled = true;
				break;
			case WM_IME_NOTIFY:
				if (wParam == IMN_SETOPENSTATUS)
				{
					SetIMEEnabled(hWnd, false);
					m_bIMEDisabled = true;
				}
				break;
			}
		}

		return ret;
	}

	ULONGLONG m_ullLastSendOptionPacketTime = GetTickCount64();
	typedef int(__thiscall* COptionsDialog__OnCommand_t)(void* thisptr, char* szButtonName); // aka PropertyDialog::OnCommand
	COptionsDialog__OnCommand_t oCOptionsDialog__OnCommand = nullptr;
	int __fastcall COptionsDialog__OnCommand(void* thisptr, void* edx, char* szButtonName)
	{
		// 56 57 8B 7C 24 ? 68 ? ? ? ? 8B F1 57 E8 ? ? ? ? 83 C4 ? 85 C0 75 ? 8B 06 8B CE FF 90 ? ? ? ? 8B 16
		auto ret = oCOptionsDialog__OnCommand(thisptr, szButtonName);
		auto ullNow = GetTickCount64();
		if ((strcmp(szButtonName, "Apply") == 0 || strcmp(szButtonName, "OK") == 0) && ullNow - m_ullLastSendOptionPacketTime > 300)
		{
			reinterpret_cast<void(__cdecl*)()>(0x371786D0)();
			m_ullLastSendOptionPacketTime = ullNow;
		}
		return ret;
	}

	// 文件名稱含有英文必須為小寫，並且打包的Nar名稱不得更改，如果要更改需要重新打包，因為Nar結構內會寫入完整的相對路徑
	const char* szExtraNarFileNames[] = { "custom_nar" };

	typedef int(__cdecl* FS_MountNarForGameDir_t)(const char* pszGameDir, const char* pszLang);
	FS_MountNarForGameDir_t oFS_MountNarForGameDir = reinterpret_cast<FS_MountNarForGameDir_t>(0x3715BBD0);
	int(__cdecl* oFS_MountAllNarFiles)();
	int __cdecl FS_MountAllNarFiles()
	{
		for (int i = 0; i < ARRAYSIZE(szExtraNarFileNames); i++)
			oFS_MountNarForGameDir(szExtraNarFileNames[i], "");
		return oFS_MountAllNarFiles();
	}
}

namespace FontFix
{
	typedef bool(__thiscall* CWin32Font__Create_t)(void* thisptr, const char* windowsFontName, int tall, int weight, int blur, int scanlines, int flags);
	CWin32Font__Create_t oCWin32Font__Create = nullptr;
	CWin32Font__Create_t oVGui2Font__Create = nullptr;

	bool __fastcall CWin32Font__Create(void* thisptr, void* edx, const char* windowsFontName, int tall, int weight, int blur, int scanlines, int flags)
	{
		if (windowsFontName)
		{
			// Trebuchet MS: used by Legacy_CreditsFont (Radio menu C/X/Z in titles.txt)
			// Verdana: used by EngineFont (in-game PeriodicAnnouncements and console)
			// Tahoma: keep as Tahoma! Tahoma has native Windows FontLink (PMingLiU/SimSun) with 10x9/12x12 bold bitmap glyphs.
			// Microsoft JhengHei: outline font with aggressive stroke-dropping at small sizes (e.g. 錢 disappears) -> redirect to Tahoma
			if (_stricmp(windowsFontName, "Trebuchet MS") == 0 ||
				_stricmp(windowsFontName, "Verdana") == 0 ||
				_stricmp(windowsFontName, "Microsoft JhengHei") == 0)
			{
				Utils::ConsolePrint("[ FontFix ] Redirected font '%s' -> 'Tahoma' (tall: %d, weight: %d)\n", windowsFontName, tall, weight);
				windowsFontName = "Tahoma";
			}
		}
		return oCWin32Font__Create(thisptr, windowsFontName, tall, weight, blur, scanlines, flags);
	}

	bool __fastcall VGui2Font__Create(void* thisptr, void* edx, const char* windowsFontName, int tall, int weight, int blur, int scanlines, int flags)
	{
		if (windowsFontName)
		{
			if (_stricmp(windowsFontName, "Trebuchet MS") == 0 ||
				_stricmp(windowsFontName, "Verdana") == 0 ||
				_stricmp(windowsFontName, "Microsoft JhengHei") == 0)
			{
				Utils::ConsolePrint("[ FontFix-VGUI2 ] Redirected font '%s' -> 'Tahoma' (tall: %d, weight: %d)\n", windowsFontName, tall, weight);
				windowsFontName = "Tahoma";
			}
		}
		return oVGui2Font__Create(thisptr, windowsFontName, tall, weight, blur, scanlines, flags);
	}

	HFONT(WINAPI* oCreateFontA)(
		int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight,
		DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet,
		DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily,
		LPCSTR pszFaceName) = nullptr;

	HFONT WINAPI Hook_CreateFontA(
		int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight,
		DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet,
		DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily,
		LPCSTR pszFaceName)
	{
		if (pszFaceName)
		{
			if (_stricmp(pszFaceName, "Trebuchet MS") == 0 ||
				_stricmp(pszFaceName, "Verdana") == 0 ||
				_stricmp(pszFaceName, "Microsoft JhengHei") == 0)
			{
				pszFaceName = "Tahoma";
			}
		}
		return oCreateFontA(cHeight, cWidth, cEscapement, cOrientation, cWeight,
			bItalic, bUnderline, bStrikeOut, iCharSet,
			iOutPrecision, iClipPrecision, iQuality, iPitchAndFamily,
			pszFaceName);
	}
}

namespace LoginRegisterHook
{
	uintptr_t g_dwGameUI = 0;

	// Typedefs for VGUI2 controls in GameUI.dll
	typedef void* (__cdecl* pfnOperatorNew_t)(size_t size);
	typedef void* (__thiscall* ButtonConstructor_t)(void* thisptr, void* parent, const char* panelName, const char* text);
	typedef void (__thiscall* PanelSetBounds_t)(void* thisptr, int x, int y, int wide, int tall);
	typedef void (__thiscall* ButtonSetCommand_t)(void* thisptr, const char* cmd);
	typedef void* (__thiscall* FindChildByName_t)(void* thisptr, const char* name, bool recurseDown);
	typedef void (__thiscall* TextEntryGetText_t)(void* thisptr, char* buf, int bufLen);

	void* oCLoginDlg_Constructor = nullptr;
	void* oCLoginDlg_OnCommand = nullptr;

	void* __fastcall Hook_CLoginDlg_Constructor(void* thisptr, void* edx, int a2)
	{
		typedef void* (__thiscall* CLoginDlgCtor_t)(void* thisptr, int a2);
		void* pDlg = ((CLoginDlgCtor_t)oCLoginDlg_Constructor)(thisptr, a2);
		if (!pDlg || !g_dwGameUI)
			return pDlg;

		pfnOperatorNew_t pfnNew = (pfnOperatorNew_t)(g_dwGameUI + 0x209569);
		ButtonConstructor_t pfnButtonCtor = (ButtonConstructor_t)(g_dwGameUI + 0x1B2D10);
		PanelSetBounds_t pfnSetBounds = (PanelSetBounds_t)(g_dwGameUI + 0x195340);
		ButtonSetCommand_t pfnSetCommand = (ButtonSetCommand_t)(g_dwGameUI + 0x1B4670);
		FindChildByName_t pfnFindChild = (FindChildByName_t)(g_dwGameUI + 0x196ED0);

		// 1. Reposition LoginBtn to (148, 141, 92, 32)
		void* pLoginBtn = pfnFindChild(pDlg, "LoginBtn", false);
		if (pLoginBtn)
		{
			pfnSetBounds(pLoginBtn, 148, 141, 92, 32);
		}

		// 2. Reposition CloseBtn to (248, 141, 92, 32)
		void* pCloseBtn = pfnFindChild(pDlg, "CloseBtn", false);
		if (pCloseBtn)
		{
			pfnSetBounds(pCloseBtn, 248, 141, 92, 32);
		}

		// 3. Create RegisterBtn at (48, 141, 92, 32)
		void* pRegBtnMem = pfnNew(0x18C);
		if (pRegBtnMem)
		{
			void* pRegBtn = pfnButtonCtor(pRegBtnMem, pDlg, "RegisterBtn", "註冊帳號");
			if (pRegBtn)
			{
				pfnSetBounds(pRegBtn, 48, 141, 92, 32);
				pfnSetCommand(pRegBtn, "Register");
				// Ensure visible: call vtable[0x94 / 4] (Panel::SetVisible)
				(*(void (__thiscall **)(void*, int))(*(DWORD*)pRegBtn + 0x94))(pRegBtn, 1);
			}
		}

		return pDlg;
	}

	static std::string Utf8ToAnsi(const std::string& utf8)
	{
		if (utf8.empty()) return "";
		int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.length(), NULL, 0);
		if (wlen <= 0) return utf8;
		std::vector<wchar_t> wbuf(wlen);
		MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.length(), wbuf.data(), wlen);
		int alen = WideCharToMultiByte(CP_ACP, 0, wbuf.data(), wlen, NULL, 0, NULL, NULL);
		if (alen <= 0) return utf8;
		std::string ansi(alen, '\0');
		WideCharToMultiByte(CP_ACP, 0, wbuf.data(), wlen, &ansi[0], alen, NULL, NULL);
		return ansi;
	}

	static void ShowNativeMessageBox(const char* pszTitle, const char* pszMessage)
	{
		void* pGameUI = *(void**)0x375B6DBC;
		if (!pGameUI && g_dwGameUI)
		{
			typedef void* (*CreateInterfaceFn)(const char* pName, int* pReturnCode);
			CreateInterfaceFn fnCreateInterface = (CreateInterfaceFn)GetProcAddress((HMODULE)g_dwGameUI, "CreateInterface");
			if (fnCreateInterface)
				pGameUI = fnCreateInterface("GameUI007", NULL);
		}

		if (pGameUI)
		{
			typedef void (__thiscall* ShowMessageBox_t)(void* thisptr, const char* title, const char* message);
			ShowMessageBox_t fnShowMsgBox = *(ShowMessageBox_t*)(*(DWORD*)pGameUI + 0xA8);
			fnShowMsgBox(pGameUI, pszTitle, pszMessage);
			return;
		}

		MessageBoxA(NULL, pszMessage, pszTitle, MB_OK | MB_ICONINFORMATION);
	}

	char __fastcall Hook_CLoginDlg_OnCommand(void* thisptr, void* edx, const char* pszCommand)
	{
		if (pszCommand && _stricmp(pszCommand, "Register") == 0)
		{
			// Read ID and Password
			char szID[256] = {};
			char szPass[256] = {};

			void* pTextID = *(void**)((char*)thisptr + 89 * sizeof(void*));
			void* pTextPass = *(void**)((char*)thisptr + 90 * sizeof(void*));

			if (pTextID && pTextPass)
			{
				TextEntryGetText_t fnGetTextID = *(TextEntryGetText_t*)(*(DWORD*)pTextID + 596);
				TextEntryGetText_t fnGetTextPass = *(TextEntryGetText_t*)(*(DWORD*)pTextPass + 596);
				fnGetTextID(pTextID, szID, sizeof(szID));
				fnGetTextPass(pTextPass, szPass, sizeof(szPass));
			}

			std::string sUser(szID);
			std::string sPass(szPass);
			while (!sUser.empty() && (sUser.back() == ' ' || sUser.back() == '\r' || sUser.back() == '\n' || sUser.back() == '\t')) sUser.pop_back();
			while (!sPass.empty() && (sPass.back() == ' ' || sPass.back() == '\r' || sPass.back() == '\n' || sPass.back() == '\t')) sPass.pop_back();

			if (sUser.empty() || sPass.empty())
			{
				ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"請在上方輸入要註冊的帳號與密碼！").c_str());
				return 0;
			}

			if (sUser.length() < 3 || sUser.length() > 16)
			{
				ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"帳號長度需介於 3 到 16 個字元！").c_str());
				return 0;
			}

			if (sPass.length() < 4 || sPass.length() > 20)
			{
				ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"密碼長度需介於 4 到 20 個字元！").c_str());
				return 0;
			}

			for (char c : sUser)
			{
				if (!isalnum((unsigned char)c) && c != '_' && c != '-')
				{
					ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"帳號僅能使用英文字母、數字與底線！").c_str());
					return 0;
				}
			}

			// Send registration request to server on port (ntohs(m_iHostPort) + 1 or 8002)
			SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == INVALID_SOCKET)
			{
				ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"網路通訊端建立失敗！").c_str());
				return 0;
			}

			DWORD timeout = 4000; // 4 seconds
			setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
			setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

			sockaddr_in saddr = {};
			saddr.sin_family = AF_INET;
			saddr.sin_addr.s_addr = m_iHostIPAddress;
			saddr.sin_port = htons(ntohs(m_iHostPort) + 1); // default 8002

			if (connect(s, (sockaddr*)&saddr, sizeof(saddr)) != 0)
			{
				closesocket(s);
				ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"無法連線至註冊伺服器 (8002)，請確認伺服器已開啟！").c_str());
				return 0;
			}

			std::string req = "REGISTER " + sUser + " " + sPass + "\n";
			char szResp[1024] = {};
			int nRecv = 0;

			if (HookFuncs::m_iEnableSSL)
			{
				typedef void* (*fn_SSLv23_client_method)();
				typedef void* (*fn_SSL_CTX_new)(void* meth);
				typedef void (*fn_SSL_CTX_free)(void* ctx);
				typedef void* (*fn_SSL_new)(void* ctx);
				typedef int (*fn_SSL_set_fd)(void* ssl, int fd);
				typedef int (*fn_SSL_connect)(void* ssl);
				typedef int (*fn_SSL_write)(void* ssl, const void* buf, int num);
				typedef int (*fn_SSL_read)(void* ssl, void* buf, int num);
				typedef int (*fn_SSL_shutdown)(void* ssl);
				typedef void (*fn_SSL_free)(void* ssl);

				HMODULE hSSLeay = GetModuleHandleA("SSLEAY32.dll");
				if (!hSSLeay) hSSLeay = LoadLibraryA("SSLEAY32.dll");

				fn_SSLv23_client_method pfn_SSLv23_client_method = hSSLeay ? (fn_SSLv23_client_method)GetProcAddress(hSSLeay, "SSLv23_client_method") : NULL;
				fn_SSL_CTX_new pfn_SSL_CTX_new = hSSLeay ? (fn_SSL_CTX_new)GetProcAddress(hSSLeay, "SSL_CTX_new") : NULL;
				fn_SSL_CTX_free pfn_SSL_CTX_free = hSSLeay ? (fn_SSL_CTX_free)GetProcAddress(hSSLeay, "SSL_CTX_free") : NULL;
				fn_SSL_new pfn_SSL_new = hSSLeay ? (fn_SSL_new)GetProcAddress(hSSLeay, "SSL_new") : NULL;
				fn_SSL_set_fd pfn_SSL_set_fd = hSSLeay ? (fn_SSL_set_fd)GetProcAddress(hSSLeay, "SSL_set_fd") : NULL;
				fn_SSL_connect pfn_SSL_connect = hSSLeay ? (fn_SSL_connect)GetProcAddress(hSSLeay, "SSL_connect") : NULL;
				fn_SSL_write pfn_SSL_write = hSSLeay ? (fn_SSL_write)GetProcAddress(hSSLeay, "SSL_write") : NULL;
				fn_SSL_read pfn_SSL_read = hSSLeay ? (fn_SSL_read)GetProcAddress(hSSLeay, "SSL_read") : NULL;
				fn_SSL_shutdown pfn_SSL_shutdown = hSSLeay ? (fn_SSL_shutdown)GetProcAddress(hSSLeay, "SSL_shutdown") : NULL;
				fn_SSL_free pfn_SSL_free = hSSLeay ? (fn_SSL_free)GetProcAddress(hSSLeay, "SSL_free") : NULL;

				if (!pfn_SSLv23_client_method || !pfn_SSL_CTX_new || !pfn_SSL_CTX_free || !pfn_SSL_new ||
					!pfn_SSL_set_fd || !pfn_SSL_connect || !pfn_SSL_write || !pfn_SSL_read || !pfn_SSL_free)
				{
					closesocket(s);
					ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"無法載入 SSL 加密模組 (SSLEAY32.dll)！").c_str());
					return 0;
				}

				void* meth = pfn_SSLv23_client_method();
				void* ctx = pfn_SSL_CTX_new(meth);
				if (!ctx)
				{
					closesocket(s);
					ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"初始化 SSL 環境失敗！").c_str());
					return 0;
				}

				void* ssl = pfn_SSL_new(ctx);
				if (!ssl)
				{
					pfn_SSL_CTX_free(ctx);
					closesocket(s);
					ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"建立 SSL 連線物件失敗！").c_str());
					return 0;
				}

				pfn_SSL_set_fd(ssl, (int)s);

				if (pfn_SSL_connect(ssl) <= 0)
				{
					pfn_SSL_free(ssl);
					pfn_SSL_CTX_free(ctx);
					closesocket(s);
					ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"無法建立 SSL 加密連線！\n請確認伺服器已開啟 SSL 且證書配置正確。").c_str());
					return 0;
				}

				pfn_SSL_write(ssl, req.c_str(), (int)req.length());
				nRecv = pfn_SSL_read(ssl, szResp, sizeof(szResp) - 1);

				if (pfn_SSL_shutdown) pfn_SSL_shutdown(ssl);
				pfn_SSL_free(ssl);
				pfn_SSL_CTX_free(ctx);
				closesocket(s);
			}
			else
			{
				send(s, req.c_str(), (int)req.length(), 0);
				nRecv = recv(s, szResp, sizeof(szResp) - 1, 0);
				closesocket(s);
			}

			if (nRecv <= 0)
			{
				ShowNativeMessageBox("#CSO_ServerMessage_Title", Utf8ToAnsi(u8"伺服器未回應註冊結果，請稍後再試！").c_str());
				return 0;
			}

			szResp[nRecv] = '\0';
			std::string resp(szResp);

			if (resp.rfind("OK:", 0) == 0)
			{
				std::string msg = resp.substr(3);
				while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n')) msg.pop_back();
				std::string ansiMsg = Utf8ToAnsi(msg);
				ShowNativeMessageBox("#CSO_ServerMessage_Title", ansiMsg.c_str());
			}
			else if (resp.rfind("ERR:", 0) == 0)
			{
				std::string msg = resp.substr(4);
				while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n')) msg.pop_back();
				std::string ansiMsg = Utf8ToAnsi(msg);
				ShowNativeMessageBox("#CSO_ServerMessage_Title", ansiMsg.c_str());
			}
			else
			{
				std::string ansiMsg = Utf8ToAnsi(resp);
				ShowNativeMessageBox("#CSO_ServerMessage_Title", ansiMsg.c_str());
			}

			return 0;
		}

		typedef char (__thiscall* CLoginDlgOnCommand_t)(void* thisptr, const char* pszCommand);
		return ((CLoginDlgOnCommand_t)oCLoginDlg_OnCommand)(thisptr, pszCommand);
	}
}

namespace BotPatch
{
	// ---------------------------------------------------------------------------
	// Master switch.
	//
	// The whole BOT feature (lobby "虛擬對手" button, the lobby settings sync, all
	// of the mp.dll patches and the in-game /bot command) only turns on when the
	// client is launched with the -bot parameter:
	//
	//     cstrike-online.exe -bot
	//
	// Without it every bot-related hook is skipped, so mp.dll, GameUI.dll and
	// hw.dll stay byte-for-byte stock and the game runs exactly like the unmodified
	// client. The unrelated hooks (login, HackShield, font, decal, ...) are
	// unaffected either way.
	//
	// Set once, at the very top of GamePatcher(), before any hook is installed.
	// ---------------------------------------------------------------------------
	bool g_bBotFeatureEnabled = false;

	uintptr_t g_dwGameUI = 0;
	uintptr_t g_dwMp = 0;
	uintptr_t g_dwMpSize = 0;   // SizeOfImage of the loaded mp.dll, filled by PatchMpDll
	uintptr_t g_dwHw = 0;
	uintptr_t g_dwLastPatchedMp = 0;

	int g_nLobbyDifficulty = 0;
	int g_nLobbyHumanTeam = 4;
	int g_nLobbyBotTeam = 5;
	int g_nLobbyAutoBalance = 1;
	bool g_bHasLobbyBotSettings = false;

	// The lobby bot settings are deliberately NOT remembered. They are a one-shot
	// mailbox between the room-create dialog and the room that is about to be
	// created: as soon as a round has been seeded from them they are dropped, so
	// the next room only gets bots if the player opens the "虛擬對手" dialog and
	// presses OK again. A room created without touching the dialog therefore gets
	// no lobby bots at all.
	//
	// The values are reset to the defaults from cstrike/resource/
	// default_bot_setting.csv (row 1: 0 / 4 / 5 / 1) so the dialog also opens on
	// the defaults next time instead of the previous room's choice.
	void ClearLobbyBotSettings()
	{
		g_nLobbyDifficulty = 0;
		g_nLobbyHumanTeam = 4;
		g_nLobbyBotTeam = 5;
		g_nLobbyAutoBalance = 1;
		g_bHasLobbyBotSettings = false;
	}

	int g_nTargetBotTotal = -1;  // /bot <n>: the room's TOTAL bot count (-1 = not managed)
	int g_nTargetBotCount = -1;  // bots wanted on the human players' side
	int g_nDesiredEnemyBots = 0; // bots wanted on the opposing side

	// Per-side reconciliation bookkeeping.
	//
	// A bot created by BotAdd() shows up in the player counts a frame or two later,
	// so each side keeps a "pending adds" window to avoid asking for the same bot
	// twice (which would overshoot the quota).
	struct SideState
	{
		int   pendingAdds;      // bots asked for but not yet observed on this side
		int   expectedBots;     // bots we expect on this side once they land
		DWORD pendingTick;
		DWORD lastKickTick;
	};

	SideState g_sideState[3];       // indexed by side (1 and 2)
	DWORD     g_dwLastReconcileTick = 0;

	// The zombie modes reconcile the TOTAL bot count instead of a per-side quota
	// (see ReconcileZombieBotTotal) and keep their own pending window.
	int   g_nZombiePendingAdds = 0;
	int   g_nZombieExpectedTotal = 0;
	DWORD g_dwZombiePendingTick = 0;
	DWORD g_dwZombieLastKickTick = 0;

	void ResetBotReconcileState()
	{
		for (int i = 0; i < 3; i++)
		{
			g_sideState[i].pendingAdds = 0;
			g_sideState[i].expectedBots = 0;
			g_sideState[i].pendingTick = 0;
			g_sideState[i].lastKickTick = 0;
		}
		g_dwLastReconcileTick = 0;

		g_nZombiePendingAdds = 0;
		g_nZombieExpectedTotal = 0;
		g_dwZombiePendingTick = 0;
		g_dwZombieLastKickTick = 0;
	}

	// ---------------------------------------------------------------------------
	// Module-relative address helpers
	//
	// Every mp.dll address must be expressed as a module-RELATIVE offset
	// (mp.dll+0x92BC0), never as an absolute VA (0x10092BC0). Passing an absolute
	// VA where an offset is expected produces a wild call target and hard-crashes
	// the client, so all offsets are validated against the real image size.
	// ---------------------------------------------------------------------------

	uintptr_t ReadModuleImageSize(uintptr_t base)
	{
		if (!base) return 0;
		const IMAGE_DOS_HEADER* pDos = (const IMAGE_DOS_HEADER*)base;
		if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
		const IMAGE_NT_HEADERS* pNt = (const IMAGE_NT_HEADERS*)(base + pDos->e_lfanew);
		if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;
		return pNt->OptionalHeader.SizeOfImage;
	}

	// g_dwMp + offset, or 0 when the offset lies outside the mp.dll image.
	uintptr_t MpAddr(uintptr_t offset)
	{
		if (!g_dwMp) return 0;
		if (g_dwMpSize && offset >= g_dwMpSize) return 0;
		return g_dwMp + offset;
	}

	void WriteJmp(void* pAddress, void* pDestination, size_t totalBytes)
	{
		DWORD oldProtect, tempProtect;
		VirtualProtect(pAddress, totalBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
		unsigned char* pBytes = (unsigned char*)pAddress;
		pBytes[0] = 0xE9; // JMP rel32
		*(DWORD*)(pBytes + 1) = (DWORD)((uintptr_t)pDestination - ((uintptr_t)pAddress + 5));
		for (size_t i = 5; i < totalBytes; i++)
		{
			pBytes[i] = 0x90; // NOP
		}
		VirtualProtect(pAddress, totalBytes, oldProtect, &tempProtect);
	}

	// Mode tables.  Reference: cstrike_tw/resource/gamemodelist.csv
	//
	//   0  GameMode_Original        一般 / 經典
	//   1  GameMode_DeathMatch      死鬥
	//   2  GameMode_TeamDeathMatch  團隊死鬥
	//   3  GameMode_Bot             虛擬對手            <- bot mode
	//   4  GameMode_BotDM           虛擬對手 死鬥       <- bot mode
	//   5  GameMode_BotTDM          虛擬對手 團隊死鬥   <- bot mode
	//   8  GameMode_Zombi           殭屍
	//   9  GameMode_Zombi_Expand    殭屍:進化
	//  11  GameMode_Zombi_Team      殭屍團隊
	//  13  GameMode_Zombi_Team_Ann  殭屍團隊(公告)
	//  14  GameMode_Zombi_3         殭屍3
	//  15  GameMode_Scenario        劇情
	//  17  GameMode_Human_Scenario  人類劇情
	//  22  GameMode_GunDeath        槍王之王
	//  23  GameMode_LightOri        輕量經典
	//  24  GameMode_BotZombie       虛擬對手 殭屍       <- bot mode
	//  25  GameMode_BattleRush      閃擊行動
	//  26  GameMode_ZombieShelter   殭屍庇護所
	//
	// This single gate drives BOTH the lobby "虛擬對手" button (GameUI+0xA2890) and
	// the engine-level BOT machinery (the mp.dll mode checks, MaintainBotQuota, ...),
	// so the two can never disagree.
	//
	// The stock GameUI room-create code only revealed the button for the four
	// genuine bot modes (3, 4, 5, 24 - see the original check at GameUI+0xA2890:
	// "cmp eax,3 / jl hide / cmp eax,5 / jle show / cmp eax,0x18 / jne hide").
	// We widen that to the modes we actually want bots in (now also 11 and 13).
	//
	// ---------------------------------------------------------------------------
	// WHY 15 / 17 / 25 / 26 ARE *NOT* IN THIS LIST
	//
	// The engine's round restart is mp.dll sub_10191F80, and patch #8 replaces its
	// mode check at 0x1920C5 with a call to this function. The stock code is
	//
	//     cmp eax,3   / jl  default_branch     ; mode < 3
	//     cmp eax,5   / jle bot_branch         ; 3..5
	//     cmp eax,0x18/ jne default_branch     ; mode != 24
	//
	// i.e. the engine deliberately picks a DIFFERENT team/spawn-assignment branch
	// for every mode other than 3/4/5/24. Mode 15 is even special-cased a few
	// instructions earlier ("cmp eax,0xf / je 0x192047", skipping the bot-server
	// team loop) and mode 25 has its own branch at 0x192057. That branch computes
	// the team handed to sub_10172930() - the function that actually assigns the
	// team and places the player on a spawn point.
	//
	// Routing 15 / 17 / 26 down the bot branch left the player unspawned: the client
	// dropped them at the map centre instead of a spawn point (reproduced by
	// choosing the TR line-up in the room). They therefore stay OUT of this gate and
	// keep the stock round restart.
	//
	// 15 / 17 / 25 / 26 consequently have NO bot feature at all: the lobby button is
	// hidden, the engine's bot machinery is untouched, and the in-game /bot command
	// refuses to run there (see HandleInGameBotChatCommand). Those modes behave
	// exactly like the unmodified game.
	// ---------------------------------------------------------------------------
	bool __cdecl IsBotCompatibleMode(int mode)
	{
		switch (mode)
		{
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 8:
		case 9:
		case 11:   // Zombi_Team
		case 13:   // Zombi_Team_Ann
		case 14:
		case 22:
		case 23:
		case 24:
			return true;
		default:
			return false;
		}
	}

	bool __cdecl IsZombieBotMode(int mode)
	{
		switch (mode)
		{
		case 8:
		case 9:
		case 14:
		case 24:
			return true;
		default:
			return false;
		}
	}

	// Current game mode, read from g_pGameRules (mp.dll+0x387738, mode at +0x460 -
	// the same field the CGameRules constructor writes). -1 when unavailable.
	int CurrentGameMode()
	{
		if (!g_dwMp) return -1;
		__try
		{
			uintptr_t pRules = *(uintptr_t*)(g_dwMp + 0x387738);
			if (!pRules) return -1;
			return *(int*)(pRules + 0x460);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return -1;
		}
	}

	// Split a TOTAL bot count into the two sides.
	//
	// /bot <n> sets the room's total bot count and the two sides split it EVENLY;
	// an odd remainder goes to the OPPOSING side (n/2 on our side, the rest on the
	// other one): 20 -> 10/10, 21 -> 10/11, 15 -> 7/8.
	//
	// This is deliberately independent of the lobby's "我方"/"對方" values. Those
	// are ABSOLUTE per-team bot counts for the lobby-configured match
	//   FriendBotNumber -> "#CSO_Bot_Max_Human_Team" -> bot_max_human_team
	//   EnemyBotNumber  -> "#CSO_Bot_Max_Bot_Team"   -> bot_max_bot_team
	// (cstrike_tw/resource/popup_botsetting.res, cstrike/resource/default_bot_setting.csv)
	// and must not act as a weighting for /bot.
	//
	// Exception: the zombie modes have no meaningful opposing side - the stock
	// MaintainZombieBots (mp.dll+0x1B6220) puts every bot on the human side - so
	// there the whole quota goes on our side.
	void SplitBotTotal(int total, int& myShare, int& enemyShare)
	{
		if (total < 0) total = 0;

		if (IsZombieBotMode(CurrentGameMode()))
		{
			myShare = total;
			enemyShare = 0;
			return;
		}

		myShare = total / 2;
		enemyShare = total - myShare;   // odd remainder goes to the opposing side
	}

	void PrintChat(const char* msg)
	{
		if (!g_dwMp || !msg) return;
		typedef void (*pfnServerCommand_t)(const char* cmd);
		pfnServerCommand_t fnServerCommand = *(pfnServerCommand_t*)(g_dwMp + 0x386D5C);
		typedef void (*pfnServerExecute_t)();
		pfnServerExecute_t fnServerExecute = *(pfnServerExecute_t*)(g_dwMp + 0x386D60);
		if (fnServerCommand)
		{
			char buf[256];
			sprintf_s(buf, "say \"[BOT] %s\"\n", msg);
			fnServerCommand(buf);
			if (fnServerExecute)
				fnServerExecute();
		}
		Utils::ConsolePrint("[BOT] %s\n", msg);
	}

	typedef void* (*pfnUTIL_PlayerByIndex_t)(int index);

	// mp.dll+0xA5180 CountHumanClients(0): walks 1..maxClients and counts clients that
	// are connected, have a non-empty netname and are NOT bots (any team). Returns the
	// raw count, which can legitimately be 0 before the first human joins the round.
	int CountHumansRaw()
	{
		if (!g_dwMp) return 0;
		typedef int (*pfnCountHumans_t)(char);
		pfnCountHumans_t fnCountHumans = (pfnCountHumans_t)MpAddr(0xA5180);
		if (fnCountHumans)
			return fnCountHumans(0);
		return 0;
	}

	int CountActiveHumans()
	{
		int count = CountHumansRaw();
		return (count > 0) ? count : 1;
	}

	int CountActiveBots()
	{
		if (!g_dwMp) return 0;
		typedef int (*pfnCountTotal_t)();
		typedef int (*pfnCountHumans_t)(char);
		pfnCountTotal_t fnCountTotal = (pfnCountTotal_t)MpAddr(0xA5000);
		pfnCountHumans_t fnCountHumans = (pfnCountHumans_t)MpAddr(0xA5180);
		if (fnCountTotal && fnCountHumans)
		{
			int total = fnCountTotal();
			int humans = fnCountHumans(0);
			int bots = total - humans;
			return (bots >= 0) ? bots : 0;
		}
		return 0;
	}

	// Kicks up to countToKick bots. When onlySide is 1 or 2, only bots whose team
	// matches that side are considered (CBasePlayer::m_iTeam at player+280, the
	// same field CountPlayersForEachTeamName reads).
	void KickBots(int countToKick, int onlySide = 0)
	{
		if (!g_dwMp || countToKick <= 0) return;
		pfnUTIL_PlayerByIndex_t fnPlayerByIndex = (pfnUTIL_PlayerByIndex_t)MpAddr(0x230150);
		typedef void (*pfnServerCommand_t)(const char* cmd);
		pfnServerCommand_t fnServerCommand = *(pfnServerCommand_t*)(g_dwMp + 0x386D5C);
		typedef void (*pfnServerExecute_t)();
		pfnServerExecute_t fnServerExecute = *(pfnServerExecute_t*)(g_dwMp + 0x386D60);
		uintptr_t pGlobals = *(uintptr_t*)(g_dwMp + 0x386FC0);
		if (!fnPlayerByIndex || !fnServerCommand || !pGlobals) return;

		int maxClients = *(int*)(pGlobals + 144);
		uintptr_t pStringBase = *(uintptr_t*)(pGlobals + 152);
		int kicked = 0;

		for (int i = maxClients; i >= 1 && kicked < countToKick; i--)
		{
			void* pPlayer = fnPlayerByIndex(i);
			if (!pPlayer) continue;
			typedef int (__thiscall* pfnIsBot_t)(void* thisptr);
			pfnIsBot_t fnIsBot = (pfnIsBot_t)(*(uintptr_t*)(*(uintptr_t*)pPlayer + 344));
			if (fnIsBot && fnIsBot(pPlayer))
			{
				if (onlySide == 1 || onlySide == 2)
				{
					int botSide = *(int*)((uintptr_t)pPlayer + 280);
					if (botSide != onlySide) continue;
				}
				void* pEdict = *(void**)((uintptr_t)pPlayer + 4);
				if (pEdict)
				{
					int netnameOffset = *(int*)((uintptr_t)pEdict + 468);
					if (netnameOffset && pStringBase)
					{
						const char* botName = (const char*)(pStringBase + netnameOffset);
						if (botName && *botName)
						{
							char kickBuf[256];
							sprintf_s(kickBuf, "kick \"%s\"\n", botName);
							fnServerCommand(kickBuf);
							kicked++;
						}
					}
				}
			}
		}
		if (fnServerExecute && kicked > 0)
		{
			fnServerExecute();
		}
	}

	typedef char(__cdecl* BotAdd_t)(int team, bool is_custom);

	// ---------------------------------------------------------------------------
	// Per-team counting  (mp.dll+0x16FB60 CountPlayersForEachTeamName)
	//
	// CountPlayersForEachTeamName(&unassigned, &side1Humans, &side2Humans,
	//                            &spectators, &side1Bots, &side2Bots, &joining)
	// walks every "player" entity and returns the side (1 or 2) of the last human
	// it saw. It is the same helper the stock MaintainZombieBots / MaintainBotQuota
	// use to decide how many bots each side needs.
	// ---------------------------------------------------------------------------
	struct TeamCounts
	{
		int unassigned;
		int side1Humans;
		int side2Humans;
		int spectators;
		int side1Bots;
		int side2Bots;
		int joining;
		int lastHumanSide;   // 1, 2, or 0 when no human is on a real team

		int totalHumans() const { return side1Humans + side2Humans; }
		int botsOnSide(int side) const { return (side == 1) ? side1Bots : (side == 2) ? side2Bots : 0; }
	};

	bool GetTeamCounts(TeamCounts& c)
	{
		c.unassigned = c.side1Humans = c.side2Humans = 0;
		c.spectators = c.side1Bots = c.side2Bots = c.joining = 0;
		c.lastHumanSide = 0;
		if (!g_dwMp) return false;

		typedef int (__cdecl* pfnCountTeams_t)(int*, int*, int*, int*, int*, int*, int*);
		pfnCountTeams_t fnCountTeams = (pfnCountTeams_t)MpAddr(0x16FB60);
		if (!fnCountTeams) return false;

		c.lastHumanSide = fnCountTeams(&c.unassigned, &c.side1Humans, &c.side2Humans,
		                               &c.spectators, &c.side1Bots, &c.side2Bots, &c.joining);
		return true;
	}

	// The side the human players are on (1 or 2); 0 when nobody is on a real team.
	int ResolveHumanSide(const TeamCounts& c)
	{
		if (c.side1Humans > c.side2Humans) return 1;
		if (c.side2Humans > c.side1Humans) return 2;
		if (c.lastHumanSide == 1 || c.lastHumanSide == 2) return c.lastHumanSide;
		return 0;
	}

	// BotAdd() has its own team encoding: 0 = T, 1 = CT. This was confirmed in
	// sub_100937A0 -> sub_10172930, where case 1 stores team 1 and the matching
	// failure message is "#Terrorists_Full". CountPlayersForEachTeamName uses
	// 1 = T, 2 = CT, so the natural mapping is simply side - 1.
	//
	// The engine re-assigns teams while the competitive modes run, so rather than
	// trusting that derivation we confirm it at runtime: ReconcileBotCount() looks
	// at where the bots actually landed and flips this flag if they turned up on
	// the wrong side.
	bool g_bInvertBotTeam = false;

	int SideToBotAddTeam(int side)
	{
		if (side != 1 && side != 2) return 1;   // unknown -> CT
		return g_bInvertBotTeam ? (2 - side) : (side - 1);
	}

	const char* SideName(int side)
	{
		return (side == 1) ? "T" : (side == 2) ? "CT" : "?";
	}

	// Neutralise the "Team is stacked" guard: mp.dll sub_101E0950 reads the
	// mp_limitteams value straight out of the game rules object, and sub_100937A0
	// refuses to spawn a bot when the target team would exceed it. This silently
	// kills quota top-ups once humans and bots already share a team. mp_autotam-
	// balance would likewise shuffle our freshly added bots onto the other team.
	//
	// Both cvars are therefore pinned to 0 while a bot quota is active and restored
	// as soon as the quota is cleared. (The game's own error message recommends
	// exactly this: "set mp_limitteams and mp_autoteambalance to zero".)
	float g_flSavedLimitTeams = -1.0f;
	float g_flSavedAutoBalance = -1.0f;

	void DisableTeamLimitChecks()
	{
		if (!g_dwMp || g_flSavedLimitTeams >= 0.0f) return;

		typedef float(*pfnGetCvarFloat_t)(const char* cvar);
		typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
		pfnGetCvarFloat_t fnGet = *(pfnGetCvarFloat_t*)(g_dwMp + 0x386DA8);
		pfnCvar_SetValue_t fnSet = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
		if (!fnGet || !fnSet) return;

		g_flSavedLimitTeams = fnGet("mp_limitteams");
		g_flSavedAutoBalance = fnGet("mp_autoteambalance");
		fnSet("mp_limitteams", 0.0f);
		fnSet("mp_autoteambalance", 0.0f);
	}

	void RestoreTeamLimitChecks()
	{
		if (!g_dwMp || g_flSavedLimitTeams < 0.0f) return;

		typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
		pfnCvar_SetValue_t fnSet = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
		if (fnSet)
		{
			fnSet("mp_limitteams", g_flSavedLimitTeams);
			fnSet("mp_autoteambalance", g_flSavedAutoBalance);
		}
		g_flSavedLimitTeams = -1.0f;
		g_flSavedAutoBalance = -1.0f;
	}

	// BotAdd() (mp.dll+0x92BC0) literally begins with
	//     mov al, byte_103385A0 / test al,al / jnz -> return 0
	// i.e. a "bot subsystem already booted" latch at mp.dll+0x3385A0 that makes every
	// add fail silently while it is set. It reads 0 during normal play, but the
	// zombie round transitions can leave it set, and then a burst of adds returns
	// "accepted=0" while the total never moves - which is exactly the "increasing the
	// count does nothing" symptom. The engine is single threaded, so we can lift the
	// latch for the duration of our own synchronous burst and put it back afterwards.
	unsigned char g_bSavedBotBootLatch = 0;

	void RelaxBotBootLatch()
	{
		g_bSavedBotBootLatch = 0;
		if (!g_dwMp) return;
		unsigned char* pLatch = (unsigned char*)(g_dwMp + 0x3385A0);
		if (*pLatch == 0) return;
		g_bSavedBotBootLatch = *pLatch;
		*pLatch = 0;
	}

	void RestoreBotBootLatch()
	{
		if (!g_dwMp || g_bSavedBotBootLatch == 0) return;
		*(unsigned char*)(g_dwMp + 0x3385A0) = g_bSavedBotBootLatch;
		g_bSavedBotBootLatch = 0;
	}

	// Reconcile ONE side towards `desired`.
	//
	// nMinDeviation: only act when the gap is at least this large. Used for the
	// opposing side so we do not trade single bots back and forth with the engine's
	// own quota logic (which also maintains that side through bot_max_bot_team).
	void ReconcileSide(const char* szReason, const TeamCounts& counts, int side, int desired,
	                   bool bAllowKick, int nMinDeviation, DWORD nKickCooldownMs)
	{
		if (side != 1 && side != 2) return;

		SideState& st = g_sideState[side];
		DWORD now = GetTickCount();
		int cur = counts.botsOnSide(side);

		// Settle outstanding requests: satisfied once the bots show up, or given up
		// after 2s so a rejected add is retried instead of wedging the quota.
		if (st.pendingAdds > 0 &&
			(cur >= st.expectedBots || (now - st.pendingTick) > 2000))
		{
			st.pendingAdds = 0;
		}

		int effective = cur + st.pendingAdds;

		if (effective < desired && (desired - effective) >= nMinDeviation)
		{
			int toAdd = desired - effective;
			BotAdd_t fnBotAdd = (BotAdd_t)MpAddr(0x92BC0);
			if (!fnBotAdd) return;

			int botTeam = SideToBotAddTeam(side);
			DisableTeamLimitChecks();

			unsigned char bBootLatch = *(unsigned char*)(g_dwMp + 0x3385A0);
			RelaxBotBootLatch();
			int accepted = 0;
			for (int i = 0; i < toAdd; i++)
			{
				if (fnBotAdd(botTeam, false))
					accepted++;
			}
			RestoreBotBootLatch();

			st.pendingAdds += accepted;
			st.expectedBots = cur + st.pendingAdds;
			st.pendingTick = now;

			Utils::ConsolePrint("[SleepyHook] BotReconcile(%s): side=%s add %d as BotAddTeam=%d (accepted=%d, invert=%d, bootLatchWas=%d) | bots(T/CT)=%d/%d desired=%d\n",
				szReason, SideName(side), toAdd, botTeam, accepted,
				(int)g_bInvertBotTeam, (int)bBootLatch,
				counts.side1Bots, counts.side2Bots, desired);
		}
		else if (cur > desired && bAllowKick && (now - st.lastKickTick) > nKickCooldownMs)
		{
			int toKick = cur - desired;
			st.lastKickTick = now;
			st.pendingAdds = 0;
			st.expectedBots = 0;
			Utils::ConsolePrint("[SleepyHook] BotReconcile(%s): side=%s kick %d | bots(T/CT)=%d/%d desired=%d\n",
				szReason, SideName(side), toKick,
				counts.side1Bots, counts.side2Bots, desired);
			KickBots(toKick, side);
		}
		else if (cur >= desired)
		{
			st.pendingAdds = 0;
			st.expectedBots = 0;
		}
	}

	// Zombie modes (8 / 9 / 14 / 24): reconcile the TOTAL bot count.
	//
	// Humans and zombies share the round and the engine moves players between the
	// two sides as the infection progresses, so the bots legitimately end up on
	// BOTH sides. A per-side quota would then "migrate" the whole roster - kick the
	// zombies off the side we consider hostile and re-add them on the other one -
	// on every round transition. That is exactly the bug we hit (bots re-joining
	// every round, /bot kicking the entire zombie lineup).
	//
	// So here we only ever look at the sum and add on the side the bots already
	// sit on. Nothing is ever kicked because of which side a bot is on.
	void ReconcileZombieBotTotal(const char* szReason, const TeamCounts& counts, int humanSide,
	                             int desired, bool bAllowKick)
	{
		DWORD now = GetTickCount();

		// Count EVERY bot, not just the ones parked on team 1/2: freshly created or
		// infected bots can sit in the "unassigned" bucket for a moment, and counting
		// only the two teams made the quota look short (or long) at random.
		int curTotal = CountActiveBots();
		if (curTotal < 0) curTotal = 0;

		int addSide = (humanSide == 1 || humanSide == 2)
			? humanSide
			: ((counts.side1Bots >= counts.side2Bots) ? 1 : 2);

		if (g_nZombiePendingAdds > 0 &&
			(curTotal >= g_nZombieExpectedTotal || (now - g_dwZombiePendingTick) > 1200))
		{
			// A batch that never showed up is simply retried on the next pass.
			g_nZombiePendingAdds = 0;
		}

		int effective = curTotal + g_nZombiePendingAdds;

		if (effective < desired)
		{
			int toAdd = desired - effective;
			BotAdd_t fnBotAdd = (BotAdd_t)MpAddr(0x92BC0);
			if (!fnBotAdd) return;

			int botTeam = SideToBotAddTeam(addSide);
			DisableTeamLimitChecks();

			unsigned char bBootLatch = *(unsigned char*)(g_dwMp + 0x3385A0);
			RelaxBotBootLatch();
			int accepted = 0;
			for (int i = 0; i < toAdd; i++)
			{
				if (fnBotAdd(botTeam, false))
					accepted++;
			}
			RestoreBotBootLatch();

			g_nZombiePendingAdds += accepted;
			g_nZombieExpectedTotal = curTotal + g_nZombiePendingAdds;
			g_dwZombiePendingTick = now;

			Utils::ConsolePrint("[SleepyHook] BotReconcile(%s) [zombie total]: side=%s add %d as BotAddTeam=%d (accepted=%d, bootLatchWas=%d) | bots(T/CT)=%d/%d total=%d target=%d\n",
				szReason, SideName(addSide), toAdd, botTeam, accepted, (int)bBootLatch,
				counts.side1Bots, counts.side2Bots, curTotal, desired);
		}
		else if (curTotal > desired && bAllowKick && (now - g_dwZombieLastKickTick) > 1500)
		{
			int toKick = curTotal - desired;
			g_dwZombieLastKickTick = now;
			g_nZombiePendingAdds = 0;
			g_nZombieExpectedTotal = 0;
			Utils::ConsolePrint("[SleepyHook] BotReconcile(%s) [zombie total]: kick %d | bots(T/CT)=%d/%d total=%d target=%d\n",
				szReason, toKick, counts.side1Bots, counts.side2Bots, curTotal, desired);
			KickBots(toKick, 0);        // any side
		}
		else if (curTotal >= desired)
		{
			g_nZombiePendingAdds = 0;
			g_nZombieExpectedTotal = 0;
		}
	}

	// Drive the room's TOTAL bot count towards g_nTargetBotTotal.
	//
	// * called from the zombie round state machine (once per tick), from the
	//   RestartRound hook, and directly from the /bot chat command;
	// * throttled, and each side has its own "pending adds" window so an
	//   asynchronously connecting bot is never requested twice.
	void ReconcileBotCount(const char* szReason, bool bAllowKick)
	{
		if (!g_dwMp || g_nTargetBotTotal < 0)
			return;

		// Quota cleared (/bot 0, /bot kick) -> put mp_limitteams / mp_autoteambalance
		// back the way we found them.
		if (g_nTargetBotTotal == 0)
			RestoreTeamLimitChecks();

		TeamCounts counts;
		if (!GetTeamCounts(counts))
			return;

		// Never manage bots while the round has no human in it yet (warm-up / loading).
		// Use the raw client count, not the per-team one: the zombie modes leave
		// players "unassigned" during the freeze countdown, so the per-team counters
		// read 0 even though somebody is very much in the round.
		int curHumans = CountHumansRaw();
		if (curHumans <= 0)
			return;

		DWORD now = GetTickCount();
		if (now - g_dwLastReconcileTick < 200)
			return;
		g_dwLastReconcileTick = now;

		int humanSide = ResolveHumanSide(counts);
		if (humanSide == 0)
		{
			// No human on a real team (freeze countdown / round transition):
			// fall back to the side our bots are already sitting on.
			humanSide = (counts.side1Bots >= counts.side2Bots) ? 1 : 2;
		}

		int mode = CurrentGameMode();
		bool bZombieMode = IsZombieBotMode(mode);

		// Keep the engine's own quota logic pointed at the same numbers, so the two
		// mechanisms pull in the same direction instead of fighting each other.
		// Zombie modes need both sides open because the bots move between them.
		typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
		pfnCvar_SetValue_t fnSet = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
		if (fnSet && g_nTargetBotTotal > 0)
		{
			if (bZombieMode)
			{
				fnSet("bot_max_human_team", (float)g_nTargetBotTotal);
				fnSet("bot_max_bot_team", (float)g_nTargetBotTotal);
			}
			else
			{
				fnSet("bot_max_human_team", (float)g_nTargetBotCount);
				fnSet("bot_max_bot_team", (float)g_nDesiredEnemyBots);
			}
		}

		if (bZombieMode)
		{
			ReconcileZombieBotTotal(szReason, counts, humanSide, g_nTargetBotTotal, bAllowKick);
			return;
		}

		uintptr_t pGlobals = *(uintptr_t*)(g_dwMp + 0x386FC0);
		int maxClients = pGlobals ? *(int*)(pGlobals + 144) : 32;
		int room = maxClients - curHumans;
		if (room < 0) room = 0;

		int myTarget = g_nTargetBotCount < 0 ? 0 : g_nTargetBotCount;
		int enemyTarget = g_nDesiredEnemyBots < 0 ? 0 : g_nDesiredEnemyBots;

		// Never let the two sides together exceed the free client slots.
		int sum = myTarget + enemyTarget;
		if (sum > room)
		{
			int cut = sum - room;
			if (enemyTarget >= cut)
			{
				enemyTarget -= cut;
			}
			else
			{
				cut -= enemyTarget;
				enemyTarget = 0;
				myTarget -= cut;
				if (myTarget < 0) myTarget = 0;
			}
		}

		// Our side gets the exact target; the opposing side is only corrected on a
		// real deviation so we do not trade single bots with the engine.
		ReconcileSide(szReason, counts, humanSide, myTarget, bAllowKick, 1, 1500);
		ReconcileSide(szReason, counts, 3 - humanSide, enemyTarget, bAllowKick, 2, 2500);
	}

	// ReconcileBotCount() runs from the game's own per-tick code, so an access
	// violation inside it (bad offset, stale pointer, ...) would take the whole
	// client down. Trap it, log it, and leave the bots alone for that tick.
	void SafeReconcile(const char* szReason, bool bAllowKick)
	{
		__try
		{
			ReconcileBotCount(szReason, bAllowKick);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Utils::ConsolePrint("[SleepyHook] BotReconcile(%s) faulted and was skipped.\n", szReason);
		}
	}

	void HandleInGameBotChatCommand(const char* p)
	{
		if (!p || !g_dwMp) return;
		while (*p == ' ' || *p == '\t') p++;

		// Modes without bot support (15 Scenario, 17 Human_Scenario, 25 BattleRush,
		// 26 ZombieShelter) are left completely untouched: their round restart and
		// spawn logic must stay stock, and running our own BotAdd() burst there only
		// produced half a roster anyway. Tell the player and stop - the caller
		// (Hook_ClientCommand) then returns without forwarding to the original
		// ClientCommand(), so the "/bot ..." text itself never reaches the server.
		if (!IsBotCompatibleMode(CurrentGameMode()))
		{
			PrintChat("This game mode does not support BOTs.");
			return;
		}

		if (*p == '\0' || _stricmp(p, "help") == 0)
		{
			PrintChat("Commands: /bot <total>, /bot kick, /bot restart, /bot status, /bot invert");
			return;
		}

		if (_stricmp(p, "status") == 0 || _stricmp(p, "info") == 0)
		{
			TeamCounts counts;
			if (!GetTeamCounts(counts))
			{
				PrintChat("BOT status: mp.dll not ready.");
				return;
			}
			int humanSide = ResolveHumanSide(counts);
			int mode = CurrentGameMode();
			char buf[380];
			sprintf_s(buf, "BOT status: total=%d (myTarget=%d enemyTarget=%d mode=%d zombie=%d) humanSide=%s humans(T/CT)=%d/%d bots(T/CT)=%d/%d invert=%d booted=%d",
				g_nTargetBotTotal, g_nTargetBotCount, g_nDesiredEnemyBots,
				mode, (int)IsZombieBotMode(mode),
				SideName(humanSide),
				counts.side1Humans, counts.side2Humans,
				counts.side1Bots, counts.side2Bots,
				(int)g_bInvertBotTeam,
				(int)*(unsigned char*)(g_dwMp + 0x3385A0));
			PrintChat(buf);
			return;
		}

		if (_stricmp(p, "kick") == 0)
		{
			KickBots(32);
			g_nTargetBotCount = 0;
			g_nTargetBotTotal = 0;
			g_nDesiredEnemyBots = 0;
			ResetBotReconcileState();
			RestoreTeamLimitChecks();

			typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
			pfnCvar_SetValue_t fnCvar_SetValue = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
			if (fnCvar_SetValue)
			{
				// Zero both per-team quotas so the engine's own logic cannot
				// immediately re-add the bots we just kicked.
				fnCvar_SetValue("bot_quota", 0.0f);
				fnCvar_SetValue("bot_max_human_team", 0.0f);
				fnCvar_SetValue("bot_max_bot_team", 0.0f);
			}

			PrintChat("All BOTs kicked.");
			return;
		}
		else if (_stricmp(p, "restart") == 0)
		{
			typedef void (*pfnServerCommand_t)(const char* cmd);
			pfnServerCommand_t fnServerCommand = *(pfnServerCommand_t*)(g_dwMp + 0x386D5C);
			typedef void (*pfnServerExecute_t)();
			pfnServerExecute_t fnServerExecute = *(pfnServerExecute_t*)(g_dwMp + 0x386D60);
			if (fnServerCommand)
			{
				fnServerCommand("sv_restart 1\n");
				if (fnServerExecute) fnServerExecute();
			}
			PrintChat("Restarting round to apply changes...");
			return;
		}
		else if (isdigit((unsigned char)*p))
		{
			int target = atoi(p);
			if (target <= 0)
			{
				KickBots(32);
				g_nTargetBotCount = 0;
				g_nTargetBotTotal = 0;
				g_nDesiredEnemyBots = 0;
				ResetBotReconcileState();
				RestoreTeamLimitChecks();

				typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
				pfnCvar_SetValue_t fnCvar_SetValue = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
				if (fnCvar_SetValue)
				{
					fnCvar_SetValue("bot_quota", 0.0f);
					fnCvar_SetValue("bot_max_human_team", 0.0f);
					fnCvar_SetValue("bot_max_bot_team", 0.0f);
				}

				PrintChat("All BOTs kicked.");
				return;
			}

			uintptr_t pGlobals = *(uintptr_t*)(g_dwMp + 0x386FC0);
			int maxClients = pGlobals ? *(int*)(pGlobals + 144) : 32;
			int curHumans = CountActiveHumans();
			if (curHumans <= 0) curHumans = 1;

			if (curHumans + target > maxClients)
			{
				target = maxClients - curHumans;
				if (target < 0) target = 0;
			}

			// target is the TOTAL bot count. Split it across the two sides evenly;
			// the zombie modes and the forced-CT modes put everything on one side.
			int myShare = target, enemyShare = 0;
			SplitBotTotal(target, myShare, enemyShare);

			g_nTargetBotTotal = target;
			g_nTargetBotCount = myShare;      // what our reconcile drives
			g_nDesiredEnemyBots = enemyShare; // handed to the engine via bot_max_bot_team

			typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
			pfnCvar_SetValue_t fnCvar_SetValue = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
			if (fnCvar_SetValue)
			{
				// We own our side; the engine's own quota logic maintains the
				// opposing side to bot_max_bot_team, so the two never fight.
				// (ReconcileBotCount() re-points these every tick anyway, which is
				// what fixes the human-side mapping for the forced-CT modes.)
				fnCvar_SetValue("bot_quota", (float)target);
				fnCvar_SetValue("bot_max_human_team", (float)myShare);
				fnCvar_SetValue("bot_max_bot_team", (float)enemyShare);
			}

			// Apply right away, and keep the target asserted so every later round
			// restart (natural round end or /bot restart) reconciles to it as well.
			ResetBotReconcileState();
			SafeReconcile("chat", true);

			char buf[200];
			if (IsZombieBotMode(CurrentGameMode()))
				sprintf_s(buf, "BOT total set to %d (zombie mode: whole roster, no side split). Applying now.", target);
			else
				sprintf_s(buf, "BOT total set to %d (%d our side / %d enemy). Applying now (kept across round restarts).",
					target, myShare, enemyShare);
			PrintChat(buf);
			return;
		}
		else if (_stricmp(p, "invert") == 0)
		{
			g_bInvertBotTeam = !g_bInvertBotTeam;
			char buf[128];
			sprintf_s(buf, "BOT team mapping manually set: invert=%d.", (int)g_bInvertBotTeam);
			PrintChat(buf);
			return;
		}
		else
		{
			PrintChat("Unknown command. Usage: /bot <total>, /bot kick, /bot restart, /bot status, /bot invert");
		}
	}

	void* oPopup_BotSetting_OnCommand = nullptr;
	void* oPopup_BotSetting_Activate = nullptr;

	char __fastcall Hook_Popup_BotSetting_OnCommand(void* thisptr, void* edx, const char* pszCommand)
	{
		if (pszCommand && _stricmp(pszCommand, "OKBtn") == 0)
		{
			void* pDiffCombo = *(void**)((char*)thisptr + 0x18c);
			void* pHumanCombo = *(void**)((char*)thisptr + 0x190);
			void* pBotCombo = *(void**)((char*)thisptr + 0x194);
			void* pAutoCheck = *(void**)((char*)thisptr + 0x198);

			typedef void* (__thiscall* pfnGetActiveItemUserData_t)(void* thisptr);
			typedef int (__thiscall* pfnGetInt_t)(void* thisptr, const char* keyName, int defaultValue);
			typedef bool (__thiscall* pfnIsSelected_t)(void* thisptr);

			if (pDiffCombo)
			{
				pfnGetActiveItemUserData_t fnGetUserData = *(pfnGetActiveItemUserData_t*)(*(DWORD*)pDiffCombo + 0x388);
				if (fnGetUserData)
				{
					void* pKV = fnGetUserData(pDiffCombo);
					if (pKV)
					{
						pfnGetInt_t fnGetInt = *(pfnGetInt_t*)(*(DWORD*)pKV + 0x28);
						if (fnGetInt)
							g_nLobbyDifficulty = fnGetInt(pKV, "Difficulty", 0);
					}
				}
			}

			if (pHumanCombo)
			{
				pfnGetActiveItemUserData_t fnGetUserData = *(pfnGetActiveItemUserData_t*)(*(DWORD*)pHumanCombo + 0x388);
				if (fnGetUserData)
				{
					void* pKV = fnGetUserData(pHumanCombo);
					if (pKV)
					{
						pfnGetInt_t fnGetInt = *(pfnGetInt_t*)(*(DWORD*)pKV + 0x28);
						if (fnGetInt)
							g_nLobbyHumanTeam = fnGetInt(pKV, "Number", 0);
					}
				}
			}

			if (pBotCombo)
			{
				pfnGetActiveItemUserData_t fnGetUserData = *(pfnGetActiveItemUserData_t*)(*(DWORD*)pBotCombo + 0x388);
				if (fnGetUserData)
				{
					void* pKV = fnGetUserData(pBotCombo);
					if (pKV)
					{
						pfnGetInt_t fnGetInt = *(pfnGetInt_t*)(*(DWORD*)pKV + 0x28);
						if (fnGetInt)
							g_nLobbyBotTeam = fnGetInt(pKV, "Number", 0);
					}
				}
			}

			if (pAutoCheck)
			{
				pfnIsSelected_t fnIsSelected = *(pfnIsSelected_t*)(*(DWORD*)pAutoCheck + 0x2fc);
				if (fnIsSelected)
					g_nLobbyAutoBalance = fnIsSelected(pAutoCheck) ? 1 : 0;
			}

			if (g_nLobbyDifficulty < 0) g_nLobbyDifficulty = 0;
			if (g_nLobbyDifficulty > 7) g_nLobbyDifficulty = 7;
			if (g_nLobbyHumanTeam < 0) g_nLobbyHumanTeam = 0;
			if (g_nLobbyHumanTeam > 16) g_nLobbyHumanTeam = 16;
			if (g_nLobbyBotTeam < 0) g_nLobbyBotTeam = 0;
			if (g_nLobbyBotTeam > 16) g_nLobbyBotTeam = 16;
			g_nLobbyAutoBalance = (g_nLobbyAutoBalance != 0) ? 1 : 0;

			g_bHasLobbyBotSettings = true;
			// Initial quota straight from the lobby: "我方" bots go on our side,
			// "對方" bots on the opposing side (which the engine maintains).
			g_nTargetBotCount = g_nLobbyHumanTeam;
			g_nTargetBotTotal = g_nLobbyHumanTeam + g_nLobbyBotTeam;
			g_nDesiredEnemyBots = g_nLobbyBotTeam;

			Utils::ConsolePrint("[SleepyHook] Lobby BOT settings saved: Diff=%d, HumanTeam=%d, BotTeam=%d, AutoBalance=%d\n",
				g_nLobbyDifficulty, g_nLobbyHumanTeam, g_nLobbyBotTeam, g_nLobbyAutoBalance);

			if (g_dwHw)
			{
				uintptr_t pRoom = g_dwHw + 0x12F0600;
				*(int*)(pRoom + 0x70) = g_nLobbyDifficulty;
				*(int*)(pRoom + 0x74) = g_nLobbyHumanTeam;
				*(int*)(pRoom + 0x78) = g_nLobbyBotTeam;
				*(int*)(pRoom + 0x7C) = g_nLobbyAutoBalance;
			}
		}

		typedef char (__thiscall* pfnOnCommand_t)(void* thisptr, const char* pszCommand);
		return ((pfnOnCommand_t)oPopup_BotSetting_OnCommand)(thisptr, pszCommand);
	}

	void __fastcall Hook_Popup_BotSetting_Activate(void* thisptr, void* edx)
	{
		typedef void (__thiscall* pfnActivate_t)(void* thisptr);
		((pfnActivate_t)oPopup_BotSetting_Activate)(thisptr);

		if (g_bHasLobbyBotSettings)
		{
			void* pDiffCombo = *(void**)((char*)thisptr + 0x18c);
			void* pHumanCombo = *(void**)((char*)thisptr + 0x190);
			void* pBotCombo = *(void**)((char*)thisptr + 0x194);
			void* pAutoCheck = *(void**)((char*)thisptr + 0x198);

			typedef void (__thiscall* pfnActivateItemByRow_t)(void* thisptr, int row);
			if (pDiffCombo)
			{
				pfnActivateItemByRow_t fnActivate = *(pfnActivateItemByRow_t*)(*(DWORD*)pDiffCombo + 0x374);
				if (fnActivate) fnActivate(pDiffCombo, g_nLobbyDifficulty);
			}
			if (pHumanCombo)
			{
				pfnActivateItemByRow_t fnActivate = *(pfnActivateItemByRow_t*)(*(DWORD*)pHumanCombo + 0x374);
				if (fnActivate) fnActivate(pHumanCombo, g_nLobbyHumanTeam);
			}
			if (pBotCombo)
			{
				pfnActivateItemByRow_t fnActivate = *(pfnActivateItemByRow_t*)(*(DWORD*)pBotCombo + 0x374);
				if (fnActivate) fnActivate(pBotCombo, g_nLobbyBotTeam);
			}
			if (pAutoCheck)
			{
				typedef void (__thiscall* pfnSetSelected_t)(void* thisptr, bool state);
				pfnSetSelected_t fnSetSelected = *(pfnSetSelected_t*)(*(DWORD*)pAutoCheck + 0x2f8);
				if (fnSetSelected) fnSetSelected(pAutoCheck, g_nLobbyAutoBalance != 0);
			}
		}
	}

	// The room object (hw.dll, "this" in ecx at hw.dll+0x19F340) keeps the game mode
	// as a BYTE at +0x12. The stock code immediately after our hook point gates the
	// bot fields on exactly "3 <= mode <= 5 || mode == 24":
	//   hw.dll 0x19F437  mov al,[esi+12h] / cmp eax,3 / jl  hide
	//                    cmp eax,5 / jle show / cmp eax,18h / jne hide
	// We must honour the same restriction, otherwise the lobby bot settings leak
	// into modes that have no lobby bot UI at all (e.g. 26 ZombieShelter) and the
	// engine happily spawns bots there. IsBotCompatibleMode() is our (widened)
	// version of that stock check.
	//
	// IMPORTANT: the room object is a SINGLETON (hw.dll+0x12F0600) that outlives the
	// room, and this function feeds its bot fields straight into the server startup
	// script - hw.dll+0x19F4B8..0x19F4B1E reads [esi+0x70], [esi+0x74], [esi+0x78]
	// and [esi+0x7C] and passes them to the script builder (vtable+0x128). So simply
	// skipping the write is NOT enough to clear a previous room's settings: they
	// would be picked up again by the next room. We must actively write the fields.
	//
	// Native bot modes (3 / 4 / 5 / 24) have their own stock handling, so when the
	// player did not confirm the dialog we hand them the CSV defaults instead of
	// zero, and everything else gets a hard zero (= no bots).
	bool __cdecl IsNativeBotMode(int mode)
	{
		return (mode == 3 || mode == 4 || mode == 5 || mode == 24);
	}

	void __stdcall OnBuildStartupScript(void* pRoom)
	{
		if (!pRoom) return;

		int mode = *(unsigned char*)((char*)pRoom + 0x12);
		if (!IsBotCompatibleMode(mode))
			return;

		if (g_bHasLobbyBotSettings)
		{
			*(int*)((char*)pRoom + 0x70) = g_nLobbyDifficulty;
			*(int*)((char*)pRoom + 0x74) = g_nLobbyHumanTeam;
			*(int*)((char*)pRoom + 0x78) = g_nLobbyBotTeam;
			*(int*)((char*)pRoom + 0x7C) = g_nLobbyAutoBalance;
			return;
		}

		// No lobby confirmation for this room. Overwrite the singleton's fields,
		// otherwise the previous room's numbers would still be in there and would be
		// baked into this room's startup script.
		if (IsNativeBotMode(mode))
		{
			// Native bot modes keep working with the shipped defaults
			// (cstrike/resource/default_bot_setting.csv, row 1).
			*(int*)((char*)pRoom + 0x70) = 0;
			*(int*)((char*)pRoom + 0x74) = 4;
			*(int*)((char*)pRoom + 0x78) = 5;
			*(int*)((char*)pRoom + 0x7C) = 1;
		}
		else
		{
			*(int*)((char*)pRoom + 0x70) = 0;
			*(int*)((char*)pRoom + 0x74) = 0;
			*(int*)((char*)pRoom + 0x78) = 0;
			*(int*)((char*)pRoom + 0x7C) = 0;
		}
	}

	__declspec(naked) void Hook_BuildStartupScript_Thunk()
	{
		__asm
		{
			pushad
			push ecx // pRoom (0x383F0600) is in ecx
			call OnBuildStartupScript
			popad
			sub esp, 0x14
			push esi
			mov esi, ecx
			mov edx, g_dwHw
			add edx, 0x19F346
			jmp edx
		}
	}

	__declspec(naked) void Hook_GameUI_BotButtonVisibility()
	{
		__asm
		{
			push eax // mode
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jnz loc_show
			mov edx, g_dwGameUI
			add edx, 0xA28B1
			jmp edx
		loc_show:
			mov edx, g_dwGameUI
			add edx, 0xA289F
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_MaintainBotQuota_ModeCheck()
	{
		__asm
		{
			push eax // mode
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jz loc_skip
			mov edx, g_dwMp
			add edx, 0x92EEA
			jmp edx
		loc_skip:
			mov edx, g_dwMp
			add edx, 0x930B1
			jmp edx
		}
	}

	void __cdecl OnGameRulesConstructor(void* pGameRules, int mode)
	{
		// New map -> drop any bookkeeping from the previous one.
		ResetBotReconcileState();

		// Fall back to reading the mode out of the CGameRules object (it lives at
		// g_pGameRules+0x460) when the hook could not hand it to us.
		if (mode < 0 && pGameRules)
			mode = *(int*)((char*)pGameRules + 0x460);

		if (!IsBotCompatibleMode(mode))
		{
			// No bot support for this mode, so there is nothing to seed from the
			// lobby and nothing for our reconciler to drive.
			g_nTargetBotCount = -1;
			g_nTargetBotTotal = -1;
			g_nDesiredEnemyBots = 0;
			return;
		}

		if (g_bHasLobbyBotSettings)
		{
			// Initial quota straight from the lobby: "我方" bots go on our side,
			// "對方" bots on the opposing side.
			g_nTargetBotCount = g_nLobbyHumanTeam;
			g_nTargetBotTotal = g_nLobbyHumanTeam + g_nLobbyBotTeam;
			g_nDesiredEnemyBots = g_nLobbyBotTeam;
		}
		else if (mode == 24)
		{
			g_nTargetBotCount = 11;
			g_nTargetBotTotal = 11;
			g_nDesiredEnemyBots = 0;
		}
		else
		{
			g_nTargetBotCount = -1;
			g_nTargetBotTotal = -1;
			g_nDesiredEnemyBots = 0;
		}

		if (g_dwMp && g_bHasLobbyBotSettings)
		{
			typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
			pfnCvar_SetValue_t fnCvar_SetValue = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
			if (fnCvar_SetValue)
			{
				fnCvar_SetValue("bot_difficulty", (float)g_nLobbyDifficulty);
				fnCvar_SetValue("bot_max_human_team", (float)g_nLobbyHumanTeam);
				fnCvar_SetValue("bot_max_bot_team", (float)g_nLobbyBotTeam);
				fnCvar_SetValue("bot_auto_balance_bot_team", (float)g_nLobbyAutoBalance);
				fnCvar_SetValue("bot_quota", (float)(g_nLobbyHumanTeam + g_nLobbyBotTeam));
			}
		}
		else if (g_dwMp && !IsNativeBotMode(mode))
		{
			// No lobby confirmation for this round. The bot_* cvars are ENGINE cvars
			// that survive across rooms, and the engine's own quota logic
			// (MaintainBotQuota) maintains the bot count from them - so a stale
			// "bot_max_human_team 10 / bot_max_bot_team 10" from the previous room
			// would keep spawning 20 bots here even though this room was never
			// configured. Clear them.
			//
			// Native bot modes (3 / 4 / 5 / 24) are skipped: their startup script
			// legitimately carries the shipped defaults and must not be zeroed.
			typedef void (*pfnCvar_SetValue_t)(const char* cvar, float value);
			pfnCvar_SetValue_t fnCvar_SetValue = *(pfnCvar_SetValue_t*)(g_dwMp + 0x386DB0);
			if (fnCvar_SetValue)
			{
				fnCvar_SetValue("bot_difficulty", 0.0f);
				fnCvar_SetValue("bot_max_human_team", 0.0f);
				fnCvar_SetValue("bot_max_bot_team", 0.0f);
				fnCvar_SetValue("bot_auto_balance_bot_team", 0.0f);
				fnCvar_SetValue("bot_quota", 0.0f);
			}
		}

		// The lobby values have now been handed to this round, so forget them. The
		// next room only gets bots if the player opens the "虛擬對手" dialog and
		// presses OK again - a room created without doing that gets none.
		if (g_bHasLobbyBotSettings)
			ClearLobbyBotSettings();
	}

	__declspec(naked) void Hook_Mp_GameRules_BotModeCheck()
	{
		__asm
		{
			mov [esi + 0x46C], eax   // original behaviour (m_bIsBotMode)
			push eax                 // keep it for the original code path
			push edi                 // arg2: mode is in edi
			push esi                 // arg1: thisptr (CGameRules)
			call OnGameRulesConstructor
			add esp, 8
			pop eax
			mov edx, g_dwMp
			add edx, 0x1DEFEB
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_ZombieBotModeFlag()
	{
		__asm
		{
			mov [esi + 0x182], al
			push edi // mode is in edi
			call IsZombieBotMode
			add esp, 4
			mov [esi + 0x183], al // m_bIsZombieBotMode!
			mov edx, g_dwMp
			add edx, 0x1DF17A
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_BotQuotaMatch_ModeCheck()
	{
		__asm
		{
			push eax // mode
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jz loc_quota_zero
			mov edx, g_dwMp
			add edx, 0x1DEE87
			jmp edx
		loc_quota_zero:
			mov edx, g_dwMp
			add edx, 0x1DEE80
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_WaitEnemy_ModeCheck()
	{
		__asm
		{
			push eax
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jnz loc_bypass
			mov edx, g_dwMp
			add edx, 0x191E82
			jmp edx
		loc_bypass:
			mov edx, g_dwMp
			add edx, 0x191F5D
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_RoundFreeze_ModeCheck()
	{
		__asm
		{
			push eax
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jnz loc_bot
			mov edx, g_dwMp
			add edx, 0x192135
			jmp edx
		loc_bot:
			mov edx, g_dwMp
			add edx, 0x1920D4
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_CountPlayers_ModeCheck()
	{
		__asm
		{
			push eax
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jnz loc_bot
			mov edx, g_dwMp
			add edx, 0x91CAC
			jmp edx
		loc_bot:
			mov edx, g_dwMp
			add edx, 0x91C1F
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_PlayerEntityBotFlag_ModeCheck()
	{
		__asm
		{
			push eax
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jnz loc_bot
			mov edx, g_dwMp
			add edx, 0x87C82
			jmp edx
		loc_bot:
			mov edx, g_dwMp
			add edx, 0x87C50
			jmp edx
		}
	}

	__declspec(naked) void Hook_Mp_GameRulesIsBot_ModeCheck()
	{
		__asm
		{
			push eax
			call IsBotCompatibleMode
			add esp, 4
			test al, al
			jnz loc_bot
			mov edx, g_dwMp
			add edx, 0x1A08BE
			jmp edx
		loc_bot:
			mov edx, g_dwMp
			add edx, 0x1A08BB
			jmp edx
		}
	}


	void (__cdecl* oClientCommand)(void* pEntity) = nullptr;
	void __cdecl Hook_ClientCommand(void* pEntity)
	{
		typedef const char* (*pfnCmd_Argv_t)(int index);
		typedef int (*pfnCmd_Argc_t)();
		pfnCmd_Argv_t fnCmd_Argv = *(pfnCmd_Argv_t*)(g_dwMp + 0x386E10);
		pfnCmd_Argc_t fnCmd_Argc = *(pfnCmd_Argc_t*)(g_dwMp + 0x386E14);

		if (fnCmd_Argv && fnCmd_Argc)
		{
			const char* cmd = fnCmd_Argv(0);
			if (cmd && (_stricmp(cmd, "say") == 0 || _stricmp(cmd, "say_team") == 0) && fnCmd_Argc() > 1)
			{
				std::string chatLine;
				for (int i = 1; i < fnCmd_Argc(); i++)
				{
					if (i > 1) chatLine += " ";
					const char* arg = fnCmd_Argv(i);
					if (arg) chatLine += arg;
				}

				size_t start = 0;
				while (start < chatLine.length() && (chatLine[start] == ' ' || chatLine[start] == '\t' || chatLine[start] == '"'))
					start++;

				if (chatLine.compare(start, 4, "/bot") == 0)
				{
					const char* p = chatLine.c_str() + start + 4;
					while (*p == ' ' || *p == '\t') p++;

					HandleInGameBotChatCommand(p);
					return;
				}
			}
		}

		if (oClientCommand)
			oClientCommand(pEntity);
	}

	void* oMaintainZombieBots = nullptr;
	char __fastcall Hook_Mp_MaintainZombieBots(void* thisptr, void* edx)
	{
		if (!g_dwMp) return 1;

		// Original body hard-codes "keep 12 bots (22 once >5 humans)" and calls
		// BotAdd() in a loop every tick. We suppress that hard-coded target and run
		// our own target-driven reconciliation on the exact same tick, which is what
		// makes the quota self-heal after every round restart.
		SafeReconcile("MaintainZombieBots", true);
		return 1;
	}

	void* oRestartRound = nullptr;
	char __stdcall Hook_RestartRound(int a1)
	{
		typedef char (__stdcall* pfnRestartRound_t)(int a1);
		char ret = ((pfnRestartRound_t)oRestartRound)(a1);

		// A round restart invalidates any in-flight add/kick bookkeeping, so start
		// from a clean slate and reconcile immediately.
		ResetBotReconcileState();
		SafeReconcile("RestartRound", true);

		return ret;
	}

	void PatchMpDll(uintptr_t dwMp)
	{
		if (!g_bBotFeatureEnabled)      // no -bot parameter -> mp.dll stays stock
			return;
		if (!dwMp || g_dwLastPatchedMp == dwMp)
			return;

		g_dwLastPatchedMp = dwMp;
		g_dwMp = dwMp;
		g_dwMpSize = ReadModuleImageSize(dwMp);
		Utils::ConsolePrint("[SleepyHook] mp.dll base=0x%p size=0x%X\n", (void*)dwMp, (unsigned)g_dwMpSize);

		// 1. Dedicated server drop limit bypass (0xEC0D5)
		unsigned char* pTarget = (unsigned char*)(dwMp + 0xEC0D5);
		if (memcmp(pTarget, "\x0F\x84\xEE\x04\x00\x00", 6) == 0)
		{
			WriteBytes(pTarget, (void*)"\x90\x90\x90\x90\x90\x90", 6);
			Utils::ConsolePrint("[SleepyHook] Successfully hooked mp.dll at 0x%p (Bypassed pfnIsDedicatedServer drop limit)!\n", pTarget);
		}
		else
		{
			uintptr_t dwSig = Utils::FindSignature("mp.dll", "83 EC 64 53 55 56 8B F1 57 89 74 24 20 FF 15 ? ? ? ? 85 C0 0F 84");
			if (dwSig)
			{
				unsigned char* pSigTarget = (unsigned char*)(dwSig + 21);
				if (memcmp(pSigTarget, "\x0F\x84", 2) == 0)
				{
					WriteBytes(pSigTarget, (void*)"\x90\x90\x90\x90\x90\x90", 6);
					Utils::ConsolePrint("[SleepyHook] Successfully hooked mp.dll via signature at 0x%p!\n", pSigTarget);
				}
			}
		}

		// 2. MaintainBotQuota mode check (0x92ECA, 32 bytes)
		WriteJmp((void*)(dwMp + 0x92ECA), Hook_Mp_MaintainBotQuota_ModeCheck, 32);

		// 3. GameRules constructor m_bIsBotMode (0x1DEFD0, 27 bytes)
		WriteJmp((void*)(dwMp + 0x1DEFD0), Hook_Mp_GameRules_BotModeCheck, 27);

		// 4. GameRules constructor m_bIsZombieBotMode (0x1DF168, 18 bytes)
		WriteJmp((void*)(dwMp + 0x1DF168), Hook_Mp_ZombieBotModeFlag, 18);

		// 5. MaintainZombieBots (0x1B6220) Hook -> suppresses original hardcoded 12/22 bot maintenance loop
		MH_InlineHook((void*)(dwMp + 0x1B6220), Hook_Mp_MaintainZombieBots, oMaintainZombieBots);

		// 6. bot_quota_match mode check (0x1DEE71, 15 bytes)
		WriteJmp((void*)(dwMp + 0x1DEE71), Hook_Mp_BotQuotaMatch_ModeCheck, 15);

		// 7. Round start WaitEnemy check (0x191E6B, 23 bytes)
		WriteJmp((void*)(dwMp + 0x191E6B), Hook_Mp_WaitEnemy_ModeCheck, 23);

		// 8. RoundFreeze bypass (0x1920C5, 15 bytes)
		WriteJmp((void*)(dwMp + 0x1920C5), Hook_Mp_RoundFreeze_ModeCheck, 15);

		// 9. CountPlayersForEachTeamName (0x91C08, 23 bytes)
		WriteJmp((void*)(dwMp + 0x91C08), Hook_Mp_CountPlayers_ModeCheck, 23);

		// 10. PlayerEntityBotFlag (0x87C41, 15 bytes)
		WriteJmp((void*)(dwMp + 0x87C41), Hook_Mp_PlayerEntityBotFlag_ModeCheck, 15);

		// 11. GameRulesIsBot (0x1A08AC, 15 bytes)
		WriteJmp((void*)(dwMp + 0x1A08AC), Hook_Mp_GameRulesIsBot_ModeCheck, 15);

		// 12. ClientCommand hook (0x175890) for chat (/bot)
		MH_InlineHook((void*)(dwMp + 0x175890), Hook_ClientCommand, (void*&)oClientCommand);

		// 13. RestartRound hook (0x19ADD0) for round restart bot quota synchronization
		MH_InlineHook((void*)(dwMp + 0x19ADD0), Hook_RestartRound, (void*&)oRestartRound);

		Utils::ConsolePrint("[SleepyHook] Successfully unlocked BOT support in mp.dll (all patches applied)!\n");
	}

	typedef int (__cdecl* pfnLoadServerDll_t)(const char* lpLibFileName);
	pfnLoadServerDll_t oLoadServerDll = nullptr;

	int __cdecl Hook_LoadServerDll(const char* lpLibFileName)
	{
		int ret = oLoadServerDll(lpLibFileName);
		HMODULE hMp = GetModuleHandleA("mp.dll");
		if (hMp)
		{
			PatchMpDll((uintptr_t)hMp);
		}
		return ret;
	}
}

DWORD WINAPI SubModulePatcher()
{
	uintptr_t dwGameUI = NULL;
	uintptr_t dwClient = NULL;
	while (true)
	{
		dwGameUI = (uintptr_t)GetModuleHandleA("GameUI.dll");
		dwClient = (uintptr_t)GetModuleHandleA("client.dll");
		if (dwGameUI && dwClient)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	// 掛載登入介面 CLoginDlg 註冊按鈕與指令處理
	LoginRegisterHook::g_dwGameUI = dwGameUI;
	MH_InlineHook((void*)(dwGameUI + 0x60190), LoginRegisterHook::Hook_CLoginDlg_Constructor, LoginRegisterHook::oCLoginDlg_Constructor);
	MH_InlineHook((void*)(dwGameUI + 0x603B0), LoginRegisterHook::Hook_CLoginDlg_OnCommand, LoginRegisterHook::oCLoginDlg_OnCommand);

	// 解除 GameUI.dll 房間左下角「虛擬對手」設定按鈕顯示限制 (0xA2890, 15 bytes)
	// 以及 Popup_BotSetting 的大廳 BOT 設定同步 —— 只在 -bot 參數下啟用。
	if (BotPatch::g_bBotFeatureEnabled)
	{
		BotPatch::g_dwGameUI = dwGameUI;
		BotPatch::WriteJmp((void*)(dwGameUI + 0xA2890), BotPatch::Hook_GameUI_BotButtonVisibility, 15);
		Utils::ConsolePrint("[SleepyHook] Successfully hooked GameUI.dll for Bot Setting button visibility!\n");

		// 掛鉤 GameUI.dll Popup_BotSetting::OnCommand (0x9E820) 攔截 OKBtn 保存玩家自訂 BOT 設定
		MH_InlineHook((void*)(dwGameUI + 0x9E820), BotPatch::Hook_Popup_BotSetting_OnCommand, (void*&)BotPatch::oPopup_BotSetting_OnCommand);
		// 掛鉤 GameUI.dll Popup_BotSetting::Activate (0xA04A0) 恢復玩家自訂 BOT 設定
		MH_InlineHook((void*)(dwGameUI + 0xA04A0), BotPatch::Hook_Popup_BotSetting_Activate, (void*&)BotPatch::oPopup_BotSetting_Activate);
		Utils::ConsolePrint("[SleepyHook] Successfully hooked GameUI.dll Popup_BotSetting for Lobby Bot synchronization!\n");
	}
	else
	{
		Utils::ConsolePrint("[SleepyHook] BOT feature disabled (no -bot parameter) - GameUI.dll left untouched.\n");
	}

	// 等待其餘模組與記憶體初始化完成
	std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	HookFuncs::oCOptionsDialog__OnCommand = reinterpret_cast<HookFuncs::COptionsDialog__OnCommand_t>(dwGameUI + 0x1E3220);
	// Vtable hook
	MH_WriteDWORD((void*)(dwGameUI + 0x2670CC), (DWORD)&HookFuncs::COptionsDialog__OnCommand);

	// 隼雷(Thunderbolt)射擊貼圖修正
	uintptr_t dwEV_HLDM_DecalGunshot = Utils::FindSignature("client.dll", "83 FE 25 74 ? 83 FE 29 74 ?");
	if (dwEV_HLDM_DecalGunshot)
		WriteBytes((void*)(dwEV_HLDM_DecalGunshot + 3), (void*)"\x90\x90", 2);

	// FontFix for vgui2.dll (if used)
	uintptr_t dwVGui2 = (uintptr_t)GetModuleHandleA("vgui2.dll");
	if (dwVGui2)
	{
		MH_InlineHook((void*)(dwVGui2 + 0x1F300), FontFix::VGui2Font__Create, (void*&)FontFix::oVGui2Font__Create);
	}

	return 1;
}

DWORD WINAPI MpDllPatcher(LPVOID)
{
	// The bot feature is opt-in (-bot). Without it this thread has nothing to do:
	// PatchMpDll() would no-op anyway, so just exit instead of spinning.
	if (!BotPatch::g_bBotFeatureEnabled)
		return 0;

	while (true)
	{
		HMODULE hMp = GetModuleHandleA("mp.dll");
		if (hMp)
		{
			BotPatch::PatchMpDll((uintptr_t)hMp);
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
		else
		{
			BotPatch::g_dwLastPatchedMp = 0;
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
		}
	}
	return 0;
}

// The bundled CCommandLine::CheckParm() is a plain case-SENSITIVE strstr() over the
// raw command line, so "-bot" would also match "-botsomething" and "-BOT" would not
// match at all. Do a real token match (case-insensitive, quotes stripped) instead.
bool HasCommandLineSwitch(const char* pszSwitch)
{
	if (!pszSwitch || !*pszSwitch) return false;

	ICommandLine* pCmdLine = CommandLine();
	if (!pCmdLine) return false;

	const char* pszCmdLine = pCmdLine->GetCmdLine();
	if (!pszCmdLine) return false;

	const size_t nLen = strlen(pszSwitch);
	const char* p = pszCmdLine;

	while (*p)
	{
		while (*p == ' ' || *p == '\t') p++;
		if (!*p) break;

		bool bQuoted = false;
		if (*p == '"') { bQuoted = true; p++; }

		const char* pStart = p;
		const char* pEnd = p;
		while (*pEnd)
		{
			if (bQuoted) { if (*pEnd == '"') break; }
			else if (*pEnd == ' ' || *pEnd == '\t') break;
			pEnd++;
		}

		if ((size_t)(pEnd - pStart) == nLen && _strnicmp(pStart, pszSwitch, nLen) == 0)
			return true;

		p = (*pEnd) ? pEnd + 1 : pEnd;
	}
	return false;
}

void GamePatcher() 
{
	Utils::AttachConsole();

	// ---------------------------------------------------------------------------
	// Master switch for the whole BOT feature. Launch with "-bot" to turn it on;
	// without it the client runs completely stock (mp.dll / GameUI.dll / hw.dll are
	// never touched by the bot patches).
	// ---------------------------------------------------------------------------
	BotPatch::g_bBotFeatureEnabled = HasCommandLineSwitch("-bot");
	Utils::ConsolePrint("[SleepyHook] BOT feature: %s\n",
		BotPatch::g_bBotFeatureEnabled
			? "ENABLED (-bot parameter found)"
			: "DISABLED (no -bot parameter; running stock game logic)");

	std::string sIpAddr = CommandLine()->GetParmValue("-ip");
	if (sIpAddr.empty())
		sIpAddr = "127.0.0.1";
	unsigned short nPort = CommandLine()->GetParmValue("-port", 0);
	if (nPort == 0)
		nPort = 8001;
	m_iHostIPAddress = inet_addr(sIpAddr.c_str());
	m_iHostPort = htons(nPort);
	if (CommandLine()->CheckParm("-nossl") != NULL)
		HookFuncs::m_iEnableSSL = 0;
	else
		HookFuncs::m_iEnableSSL = 1;

	Utils::ConsolePrint("IP: %s\n", sIpAddr.c_str());
	Utils::ConsolePrint("Port: %d\n", nPort);
	Utils::ConsolePrint("SSL: %s\n", HookFuncs::m_iEnableSSL ? "Enabled" : "Disabled");

	MH_InlineHook((void*)0x37297D80, HackShield::SetACInit, (void*&)HackShield::oSetACInit);
	MH_InlineHook((void*)0x37442F60, HackShield::Hook2, (void*&)HackShield::oHook2);
	WriteBytes((void*)0x37297AE2, (void*)"\xEB\x5D", 2); //HackShield
	WriteBytes((void*)0x37298B40, (void*)"\xC3", 1); //HackShield

	MH_InlineHook((void*)0x374405F0, HookFuncs::SocketManager__Constructor, (void*&)HookFuncs::oSocketManager__Constructor);
	MH_InlineHook((void*)0x37444120, HookFuncs::IpRedirector, (void*&)HookFuncs::oIpRedirector);
	MH_InlineHook((void*)0x371F4470, HookFuncs::HolePunchFuncSetServerInfo, (void*&)HookFuncs::oHolePunchFuncSetServerInfo);

	MH_InlineHook((void*)0x372FFB10, RankLocationFix::RankSetPlayerInfo, (void*&)RankLocationFix::oRankSetPlayerInfo);
	MH_InlineHook((void*)0x371EDDF0, HookFuncs::CGame__WndProc, (void*&)HookFuncs::oCGame__WndProc);

	MH_InlineHook((void*)0x37442A60, CSONMWrapper::AuthUser, (void*&)CSONMWrapper::oCSONMWrapper__AuthUser);
	MH_InlineHook((void*)0x37442810, CSONMWrapper::CheckIsAge18, (void*&)CSONMWrapper::oCheckIsAge18);
	MH_InlineHook((void*)0x372FBDB0, CSONMWrapper::COutPacket__SendLoginPacket, (void*&)CSONMWrapper::oCOutPacket__SendLoginPacket);
	WriteBytes((void*)0x372207B0, (void*)"\x31\xC0", 2);
	// 修正登入帳號不存在/錯誤無任何彈窗提示反饋 (hw.dll sub_37220770 case 3 / case 10 / case 14)：
	// 原版 hw.dll 在接收到 Packet_Reply 類型 3 (InvalidName) 或 10 (SysError) 時，
	// 若 dword_383CA528 != 0 (遊戲啟動即常駐非零)，會走入 LABEL_37 調用 sub_372212F0 將錯誤字串存入內部對象而不彈窗。
	// 將條件跳轉強行改為無條件跳轉，直接呼叫 CGameUI::ShowMessageBox("#CSO_ServerMessage_Title", "#CSO_ServerMessage_InvalidName")，
	// 與密碼錯誤 (case 7) 一樣正常彈出遊戲內置「錯誤的遊戲帳號.」對話框。
	WriteBytes((void*)0x37220930, (void*)"\xEB\x23\x90\x90\x90\x90\x90\x90", 8); // case 3: InvalidName -> loc_37220955
	WriteBytes((void*)0x372209CF, (void*)"\xEB\x23\x90\x90\x90\x90\x90\x90", 8); // case 10: SysError -> loc_372209F4
	WriteBytes((void*)0x37220A6E, (void*)"\xEB\x46\x90\x90\x90\x90\x90\x90", 8); // case 14: ID_NOT_ALLOWD -> loc_37220AB6
	WriteBytes((void*)0x371861AC, (void*)"\xEB\x0A", 2); // Skip missing external texture MessageBoxA

	MH_InlineHook((void*)0x3715BD40, HookFuncs::FS_MountAllNarFiles, (void*&)HookFuncs::oFS_MountAllNarFiles);

	// FontFix: 將 VGUI 缺少中文字體鏈接的西文字體 (Trebuchet MS / Verdana) 自動重定向為支援 FontLink 的標準字體 (Tahoma)
	MH_InlineHook((void*)0x373A9C10, FontFix::CWin32Font__Create, (void*&)FontFix::oCWin32Font__Create);
	FontFix::oCreateFontA = *(decltype(FontFix::oCreateFontA)*)0x374E8118;
	void* pNewCreateFontA = (void*)FontFix::Hook_CreateFontA;
	WriteBytes((void*)0x374E8118, &pNewCreateFontA, sizeof(void*));

	// 禁用 COpenglDetect 背景反透視/OpenGL 完整性檢測執行緒 (線程入口直接 xor eax, eax; ret 4)
	// 徹底解決現代顯卡驅動/錄影覆蓋 (NVIDIA GeForce Experience nvspcap.dll / Discord / OBS 等) 觸發 Cdisasm 解析崩潰 (0xC0000005 at hw.dll+0xBEAEF)
	WriteBytes((void*)0x371BECFA, (void*)"\x31\xC0\xC2\x04\x00\x90", 6);

	// 攔截 hw.dll LoadServerDll (0x371E55B0) 在 mp.dll 載入當下第一時間同步 Patch
	// 以及 hw.dll BuildStartupScript (0x3719F340) 同步自訂大廳 BOT 設定至房間物件
	// —— 兩者都只在 -bot 參數下啟用。
	HMODULE hHw = GetModuleHandleA("hw.dll");
	uintptr_t dwHw = hHw ? (uintptr_t)hHw : 0x37100000;
	BotPatch::g_dwHw = dwHw;
	if (BotPatch::g_bBotFeatureEnabled)
	{
		MH_InlineHook((void*)(dwHw + 0x1E55B0), BotPatch::Hook_LoadServerDll, (void*&)BotPatch::oLoadServerDll);
		BotPatch::WriteJmp((void*)(dwHw + 0x19F340), BotPatch::Hook_BuildStartupScript_Thunk, 6);
		Utils::ConsolePrint("[SleepyHook] Successfully hooked hw.dll for BOT module loading & lobby synchronization!\n");
	}
	else
	{
		Utils::ConsolePrint("[SleepyHook] BOT feature disabled (no -bot parameter) - hw.dll left untouched.\n");
	}

	CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)SubModulePatcher, nullptr, 0, nullptr);
	if (BotPatch::g_bBotFeatureEnabled)
		CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)MpDllPatcher, nullptr, 0, nullptr);
}
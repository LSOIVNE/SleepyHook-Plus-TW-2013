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

void GamePatcher() 
{
	Utils::AttachConsole();
	
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

	CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)SubModulePatcher, nullptr, 0, nullptr);
}
#include <iostream>
#include <Windows.h>

DWORD WINAPI Trainer(LPVOID param)
{
	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);

	unsigned char* hook_location;

	HMODULE kernel32base = GetModuleHandle(L"kernel32.dll");
	hook_location = (unsigned char*)GetProcAddress(kernel32base, "IsDebuggerPresent");

	std::cout << std::hex << hook_location << std::endl;

	DWORD old_protect;
	VirtualProtect((void*)hook_location, 7, PAGE_EXECUTE_READWRITE, &old_protect);

	//*hook_location = 0x90;
	//*(hook_location + 1) = 0x90;
	//*(hook_location + 2) = 0x90;
	//*(hook_location + 3) = 0x90;
	//*(hook_location + 4) = 0x90;
	//*(hook_location + 5) = 0x90;
	//*(hook_location + 6) = 0x90;

	for (int i = 0; i < 7; ++i)
	{
		hook_location[i] = 0x90;
	}

	fclose(f);
	FreeConsole();
	FreeLibraryAndExitThread((HMODULE)param, 0);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_THREAD_ATTACH:  break;
	case DLL_THREAD_DETACH:  break;
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Trainer, hModule, 0, nullptr);
		DisableThreadLibraryCalls(hModule);
		break;
	}
	return TRUE;
}
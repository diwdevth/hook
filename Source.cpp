#include <Windows.h>
#include <iostream>

void MsgBoxAddy(DWORD addy, DWORD end)
{
	char szBuffer[1024];
	sprintf(szBuffer, "Addy: %02x : End: %02x", addy, end);
	MessageBox(NULL, szBuffer, "Title", MB_OK);
}

bool Hook(void* toHook, void* ourFunct, int len)
{
	if (len < 5)
		return false;
	DWORD curProtection;
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);
	//curProtection = 20
	
	memset(toHook, 0x90, len);
	//toHook = 48728c replace to 4 and number replace = 0x90 or NOP
	DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5 ;//พื้นที่ตก จุดเขียน asm
	// value average address 11829f5e 
	*(BYTE*)toHook = 0xE9;
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;//+ 1 คือเว้นที่ให้ E9 = jmp
	//E9 = jmp
	//relativeAddress = valueaddres jmp
	DWORD temp;
	VirtualProtect(toHook, len, curProtection, &temp);
	return true;
}

DWORD jmpBackAddy;
void __declspec(naked) ourFunct() {
	__asm {
		add dword ptr [edi+0x24],0x200
		mov eax, [edi + 0x24]
		jmp [jmpBackAddy]
	}
}


DWORD WINAPI MainThread(LPVOID param)
{
	int hookLength = 7;//7
	DWORD hookAddress = 0x48728C;
	jmpBackAddy = hookAddress + hookLength;
	
	Hook((void*)hookAddress, ourFunct, hookLength);

	while (true)
	{
		if (GetAsyncKeyState(VK_ESCAPE)) break;
		Sleep(50);
	}
	FreeLibraryAndExitThread((HMODULE)param, 0);

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, MainThread, hModule, 0, 0);
	}

	return TRUE;
}
#include "ps_inject.h"
#include "ps_image.h"

int ps_inject(process_t* ps, pe_t* thisMod, LPCSTR lpCodeSec, LPCSTR lpDataSec,
	LPVOID lpEntryPoint, ps_inject_t* inject)
{
	PIMAGE_SECTION_HEADER pCodeHdr = ps_get_section_header(thisMod, lpCodeSec);
	PIMAGE_SECTION_HEADER pDataHdr = ps_get_section_header(thisMod, lpDataSec);
	if (!pCodeHdr || !pDataHdr) return PS_NO_SECTIONS;

	inject->dwCodeSize = ps_section_size(pCodeHdr);
	inject->dwDataSize = ps_section_size(pDataHdr);
	inject->dwSize = inject->dwCodeSize + inject->dwDataSize + ps_page_size; //+1 page for PS_IMAGE_RDATA
	inject->Base = (ULONG_PTR)VirtualAllocEx(ps->hProcess, NULL, inject->dwSize, MEM_RESERVE, PAGE_READWRITE);
	
	ps_image_t* image = ps_image_create(thisMod, inject->Base, lpCodeSec, lpDataSec);
	if (!image)
	{
		VirtualFreeEx(ps->hProcess, (LPVOID)inject->Base, inject->dwSize, MEM_RELEASE);
		return PS_CREATE_IMAGE_FAILED;
	}

	ps_import_lib_t* lib = image->import;
	while (lib)
	{
		ps_import_thunk_t* thunk = lib->thunk;

		pe_t* pLib = ps_get_module(ps, lib->szLibName);
		if (!pLib) continue;
		pe_export_t* exp = export_load(ps, pLib);
		if (!exp) continue;

		while (thunk)
		{
			((PULONG_PTR)image->RSec[PS_IMAGE_SECTION_RDATA].pData)[thunk->dwIndex]
				= export_find_function(exp, thunk->szFuncName);
			thunk = thunk->next;
		}

		export_unload(exp);
		lib = lib->next;
	}

	for (DWORD i = 0; i < PS_IMAGE_SECTIONS; i++)
	{
		DWORD dwOldProtect;
		ULONG_PTR Addr = image->VirtualBase + image->VSec[i].dwRVA;
		VirtualAllocEx(ps->hProcess, (LPVOID)Addr, image->VSec[i].dwSize, MEM_COMMIT, PAGE_READWRITE);
		ps_write(ps, Addr, image->RSec[i].pData, image->RSec[i].dwRealSize);
		VirtualProtectEx(ps->hProcess, (LPVOID)Addr, 
			image->VSec[i].dwSize, image->VSec[i].dwFlags, &dwOldProtect);
	}

	inject->dwSize = image->dwVirtualSize;
	inject->CodeVA = image->VirtualBase + image->VSec[PS_IMAGE_SECTION_CODE].dwRVA;
	inject->DataVA = image->VirtualBase + image->VSec[PS_IMAGE_SECTION_DATA].dwRVA;
	inject->EntryPointVA = inject->CodeVA + ((ULONG_PTR)lpEntryPoint 
		- (thisMod->BaseAddress + pCodeHdr->VirtualAddress));

	ps_image_free(image);
	return PS_INJECT_OK;
}

BOOL ps_adjust_privilege(LPCSTR lpPrivilegeName)
{
	HANDLE hToken;
	LUID luidPrivilege;
	TOKEN_PRIVILEGES privileges;

	if (!LookupPrivilegeValue(NULL, lpPrivilegeName, &luidPrivilege))
		return FALSE;
	if (!OpenProcessToken(ps_this_process->hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;
	
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luidPrivilege;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &privileges, sizeof(privileges), NULL, NULL);
	CloseHandle(hToken);

	return TRUE;
}

static BYTE _ps_hijack_boot[16];

#define OP_PUSHFD 0x9C
#define OP_PUSHAD 0x60

#define OP_POPAD 0x61
#define OP_POPFD 0x9D

#define OP_CALL 0xE8
#define OP_JMP 0xE9

#define JMP_OFFSET(from,to) ((to) - (from) - 5)

BOOL ps_hijack_thread(process_t* ps, DWORD dwTid, ULONG_PTR Code)
{
	CONTEXT Ctx;
	DWORD dwOldProtect;
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION
		| THREAD_SUSPEND_RESUME
		| THREAD_GET_CONTEXT
		| THREAD_SET_CONTEXT,
		FALSE, dwTid);
	if (hThread == INVALID_HANDLE_VALUE)
		return FALSE;
	
	ZeroMemory(&Ctx, sizeof(CONTEXT));
	Ctx.ContextFlags = CONTEXT_CONTROL;

	SuspendThread(hThread);
	GetThreadContext(hThread, &Ctx);

	ULONG_PTR BootCode = (ULONG_PTR)VirtualAllocEx(ps->hProcess, NULL, 
		4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ULONG_PTR PrevAddr = Ctx.Eip;
	
	//Build shell code
	_ps_hijack_boot[0] = OP_PUSHFD;
	_ps_hijack_boot[1] = OP_PUSHAD;

	_ps_hijack_boot[2] = OP_CALL;
	*(PLONG_PTR)&_ps_hijack_boot[3] = JMP_OFFSET((LONG_PTR)BootCode + 2, (LONG_PTR)Code);
	
	_ps_hijack_boot[7] = OP_POPAD;
	_ps_hijack_boot[8] = OP_POPFD;

	_ps_hijack_boot[9] = OP_JMP;
	*(PLONG_PTR)&_ps_hijack_boot[10] = JMP_OFFSET((LONG_PTR)BootCode + 2, (LONG_PTR)PrevAddr);

	//Write
	ps_write(ps, BootCode, _ps_hijack_boot, sizeof(_ps_hijack_boot));
	VirtualProtect((LPVOID)BootCode, sizeof(_ps_hijack_boot), PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//Execute
	Ctx.Eip = BootCode;

	SetThreadContext(hThread, &Ctx);
	ResumeThread(hThread);
	CloseHandle(hThread);
	return TRUE;
}
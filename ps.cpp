#include "ps.h"
#include <Psapi.h>
#include <stdlib.h>
#include <stdio.h>

static process_t _ps_this_process;

process_t* ps_this_process = &_ps_this_process;
pe_t* ps_this_module = NULL;

DWORD ps_page_size;
DWORD ps_page_mask;
DWORD ps_page_power;

static HMODULE _hMods[1024];

static LPCSTR s_szGlobalModules[] = {
	"ntdll",
	"kernel32"
};

static BOOL _ps_is_global_module(LPCSTR lpModuleName)
{
	CHAR szModuleName[64];
	strcpy_s(szModuleName, sizeof(szModuleName), lpModuleName);
	_strlwr_s(szModuleName, sizeof(szModuleName));

	SIZE_T uNameLen = strlen(lpModuleName);
	for (DWORD i = 0; i < sizeof(s_szGlobalModules) / sizeof(LPCSTR); i++)
	{
		LPCSTR lpCurrentModule = s_szGlobalModules[i];
		SIZE_T uCurrentNameLen = strlen(lpCurrentModule);
		if (!memcmp(lpCurrentModule, szModuleName,
			min(min(uNameLen,uCurrentNameLen), sizeof(szModuleName))))
		{
			return TRUE;
		}
	}
	return FALSE;
}

static DWORD _log2(DWORD dwNum)
{
	DWORD dwPower = 0;
	while (dwNum >>= 1) dwPower++;
	return dwPower;
}

void ps_init()
{
	DWORD cbNeeded = 0;
	SYSTEM_INFO sysInfo;

	GetSystemInfo(&sysInfo);
	ps_page_size = sysInfo.dwPageSize;
	ps_page_mask = ps_page_size - 1;
	ps_page_power = _log2(ps_page_size);
	
	ps_this_process->hProcess = GetCurrentProcess();

	EnumProcessModules(ps_this_process->hProcess, _hMods, sizeof(_hMods), &cbNeeded);
	ps_this_process->dwModules = cbNeeded / sizeof(HMODULE);
	ps_this_process->pModules = (pe_t*)calloc(ps_this_process->dwModules, sizeof(pe_t));
	
	CHAR szExePath[MAX_PATH];

	GetProcessImageFileName(ps_this_process->hProcess, szExePath, MAX_PATH);
	PSTR pExeName = strrchr(szExePath, '\\') + 1;

	CHAR szModulePath[MAX_PATH];
	for (DWORD i = 0; i < ps_this_process->dwModules; i++)
	{
		pe_t* mod = &ps_this_process->pModules[i];

		mod->BaseAddress = (ULONG_PTR)_hMods[i];
		mod->pDos = (PIMAGE_DOS_HEADER)mod->BaseAddress;
		mod->pNt = (PIMAGE_NT_HEADERS)((PCHAR)mod->pDos + mod->pDos->e_lfanew);

		GetModuleFileName(_hMods[i], szModulePath, MAX_PATH);
		PSTR pModuleName = strrchr(szModulePath, '\\') + 1;
		strcpy_s(mod->szName, sizeof(mod->szName), pModuleName);
		if (!strcmp(pModuleName, pExeName))
			ps_this_process->pExe = mod;
	}

	//Find current module
	ULONG_PTR ThisFunction = (ULONG_PTR)&ps_init;
	for (DWORD i = 0; i < ps_this_process->dwModules; i++)
	{
		pe_t* mod = &ps_this_process->pModules[i];
		ULONG_PTR CodeStart = mod->BaseAddress
			+ mod->pNt->OptionalHeader.BaseOfCode;
		ULONG_PTR CodeEnd = CodeStart
			+ mod->pNt->OptionalHeader.SizeOfCode;
		if (ThisFunction >= CodeStart && ThisFunction < CodeEnd)
		{
			ps_this_module = mod;
			break;
		}
	}

	if (!ps_this_module)
	{
		//Module not found. 
		//Maybe we're not a DLL but a custom code loader/injector?
		//Anyway, redirect to EXE module.
		ps_this_module = ps_this_process->pExe;
	}
}

void ps_exit()
{
	free(ps_this_process->pModules);
}

DWORD ps_round_to_page(DWORD dwSize)
{
	return ((dwSize >> ps_page_power) + (dwSize & ps_page_mask ? 1 : 0)) << ps_page_power;
}

process_t* ps_load_process(DWORD dwPid)
{
	HANDLE hProcess;
	DWORD cbNeeded = 0;
	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == INVALID_HANDLE_VALUE) return NULL;
	process_t* ps = (process_t*)malloc(sizeof(process_t));
	ps->hProcess = hProcess;

	EnumProcessModules(ps->hProcess, _hMods, sizeof(_hMods), &cbNeeded);
	DWORD dwModules = cbNeeded / sizeof(HMODULE);
	ps->pModules = (pe_t*)calloc(dwModules, sizeof(pe_t));
	CHAR szExePath[MAX_PATH];

	GetProcessImageFileName(ps->hProcess, szExePath, MAX_PATH);
	PSTR pExeName = strrchr(szExePath, '\\') + 1;

	CHAR szModulePath[MAX_PATH];

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeaders;
	
	ps->dwModules = 0;
	for (DWORD i = 0; i < dwModules; i++)
	{
		pe_t* mod = &ps->pModules[ps->dwModules];

		mod->BaseAddress = (ULONG_PTR)_hMods[i];
		ps_read(ps, mod->BaseAddress, &dosHeader, sizeof(dosHeader));
		if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) continue;
		ps_read(ps, mod->BaseAddress + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders));
		if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) continue;
		
		SIZE_T uHdrSize = ntHeaders.OptionalHeader.SizeOfHeaders;
		PVOID pHeader = malloc(uHdrSize);
		ps_read(ps, mod->BaseAddress, pHeader, uHdrSize);

		mod->pDos = (PIMAGE_DOS_HEADER)pHeader;
		mod->pNt = (PIMAGE_NT_HEADERS)((PCHAR)mod->pDos + mod->pDos->e_lfanew);

		GetModuleFileNameEx(ps->hProcess, _hMods[i], szModulePath, MAX_PATH);
		PSTR pModuleName = strrchr(szModulePath, '\\') + 1;
		strcpy_s(mod->szName, sizeof(mod->szName), pModuleName);
		if (!strcmp(pModuleName, pExeName))
			ps->pExe = mod;

		ps->dwModules++;
	}

	return ps;
}

void ps_unload_process(process_t* ps)
{
	if (ps == ps_this_process) return;

	for (DWORD i = 0; i < ps->dwModules; i++)
		free(ps->pModules[i].pDos);
	free(ps->pModules);
	CloseHandle(ps->hProcess);
	free(ps);
}

SIZE_T ps_read(process_t* ps, ULONG_PTR Addr, LPVOID lpDst, SIZE_T Size)
{
	SIZE_T Read = 0;
	if (ps == ps_this_process)
	{
		Read = Size;
		CopyMemory(lpDst, (LPCVOID)Addr, Size);
	}
	else ReadProcessMemory(ps->hProcess, (LPCVOID)Addr, lpDst, Size, &Read);
	return Read;
}

SIZE_T ps_write(process_t* ps, ULONG_PTR Addr, LPCVOID lpSrc, SIZE_T Size)
{
	SIZE_T Write;
	if (ps == ps_this_process)
	{
		Write = Size;
		CopyMemory((LPVOID)Addr, lpSrc, Size);
	}
	else
	{
		if (!WriteProcessMemory(ps->hProcess, (LPVOID)Addr, lpSrc, Size, &Write))
			return 0;
	}
	return Write;
}

pe_t* ps_get_module(process_t* ps, LPCSTR lpModuleName)
{
	CHAR szModuleName[64];
	strcpy_s(szModuleName, sizeof(szModuleName), lpModuleName);
	_strlwr_s(szModuleName,sizeof(szModuleName));

	if (_ps_is_global_module(lpModuleName) && ps != ps_this_process)
		return ps_get_module(ps_this_process, lpModuleName);

	SIZE_T uNameLen = strlen(szModuleName);
	for (DWORD i = 0; i < ps->dwModules; i++)
	{
		CHAR szCurrentModuleName[64];
		pe_t* pe = &ps->pModules[i];
		strcpy_s(szCurrentModuleName, sizeof(szCurrentModuleName), pe->szName);
		_strlwr_s(szCurrentModuleName,sizeof(szCurrentModuleName));
		SIZE_T uCurrentNameLen = strlen(szModuleName);
		if (!memcmp(szCurrentModuleName, szModuleName,
			min(min(uNameLen,uCurrentNameLen), sizeof(szModuleName))))
		{
			return pe;
		}
	}
	return NULL;
}

static ULONG_PTR _ps_sig_scan(PCSTR pCode, DWORD dwCodeSize, LPCSTR lpSig, LPCSTR lpMask)
{
	DWORD dwSigLen = (DWORD)strlen(lpMask);
	for (DWORD i = 0; i < dwCodeSize - dwSigLen; i++)
	{
		DWORD j = 0;
		for (; j < dwSigLen; j++)
		{
			if (pCode[i + j] != lpSig[j] && lpMask[j] != '?')
				break;
		}
		if (j == dwSigLen) return i;
	}
	return 0;
}

ULONG_PTR ps_sig_scan(process_t* ps, pe_t* mod, LPCSTR lpSig, LPCSTR lpMask)
{
	ULONG_PTR CodeVA = mod->BaseAddress + mod->pNt->OptionalHeader.BaseOfCode;
	DWORD dwCodeSize = mod->pNt->OptionalHeader.SizeOfCode;
	PCHAR pCode = (PCHAR)malloc(dwCodeSize);

	ps_read(ps, CodeVA, pCode, dwCodeSize);
	ULONG_PTR Offset = _ps_sig_scan(pCode, dwCodeSize, lpSig, lpMask);
	
	free(pCode);
	return Offset ? CodeVA + Offset : 0;
}

ps_seg_t* ps_load_segment(process_t* ps, pe_t* mod, ULONG_PTR Address, DWORD dwSize)
{
	LPVOID lpData;
	
	BOOL bIsGlobal = _ps_is_global_module(mod->szName);
	if (ps == ps_this_process || bIsGlobal)
	{
		//Directly "project" segment
		lpData = (LPVOID)Address;
		if (bIsGlobal) ps = ps_this_process;
	}
	else
	{
		lpData = malloc(dwSize);
		if (!lpData) return NULL;
		if (ps_read(ps, Address, lpData, dwSize) == 0)
			return NULL;
	}
	ps_seg_t* seg = (ps_seg_t*)malloc(sizeof(ps_seg_t));
	seg->pProcess = ps;
	seg->pMod = mod;
	seg->pSeg = (PCHAR)lpData;
	seg->dwSegSize = dwSize;
	seg->dwSegRVA = (DWORD)(Address - mod->BaseAddress);

	return seg;
}

ps_seg_t* ps_load_directory(process_t* ps, pe_t* mod, UINT Dir)
{
	UINT_PTR Addr = mod->BaseAddress + mod->pNt->OptionalHeader
		.DataDirectory[Dir].VirtualAddress;
	DWORD dwSize = mod->pNt->OptionalHeader.DataDirectory[Dir].Size;
	return ps_load_segment(ps, mod, Addr, dwSize);
}

void ps_unload_segment(ps_seg_t* seg)
{
	if (seg->pProcess != ps_this_process)
		free(seg->pSeg);
	free(seg);
}

PIMAGE_SECTION_HEADER ps_get_section_header(pe_t* mod, LPCSTR lpSectionName)
{
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
		((PCHAR)mod->pNt + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < mod->pNt->FileHeader.NumberOfSections; i++)
	{
		SIZE_T uNameLen = strlen(lpSectionName);
		if (!memcmp(pSection->Name, lpSectionName, min(uNameLen, 8)))
			return pSection;
		pSection++;
	}
	return NULL;
}

LPVOID ps_find_section(ps_seg_t* seg, LPCSTR lpSectionName)
{
	PIMAGE_SECTION_HEADER pSection = ps_get_section_header(seg->pMod, lpSectionName);
	if (!pSection) return NULL;
	return ps_segment_addr(seg, pSection->VirtualAddress);
}

DWORD ps_section_size(PIMAGE_SECTION_HEADER pSection)
{
	DWORD dwSize = pSection->PointerToRawData
		? pSection->SizeOfRawData : pSection->Misc.VirtualSize;
	return ps_round_to_page(dwSize);
}

BOOL ps_is_in_directory(pe_t* pe, UINT Dir, ULONG_PTR Addr)
{
	PIMAGE_DATA_DIRECTORY pDir = &pe->pNt->OptionalHeader.DataDirectory[Dir];
	ULONG_PTR Start = pe->BaseAddress + pDir->VirtualAddress;
	ULONG_PTR End = Start + pDir->Size;
	return (Addr >= Start) && (Addr < End);
}

ULONG_PTR export_get_function(pe_export_t* exp, WORD wOrdinal)
{
	PIMAGE_DATA_DIRECTORY pExportDir = &exp->pMod->pNt->OptionalHeader
		.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		ps_directory(exp, IMAGE_DIRECTORY_ENTRY_EXPORT);
	PDWORD pFunctionRVA = (PDWORD)ps_segment_addr(exp, pExport->AddressOfFunctions);
	DWORD dwExportEntry = pFunctionRVA[wOrdinal - pExport->Base];
	ULONG_PTR Addr = exp->pMod->BaseAddress + dwExportEntry;
	if (ps_is_in_directory(exp->pMod, IMAGE_DIRECTORY_ENTRY_EXPORT, Addr))
	{
		//Forwarder RVA
		CHAR szName[64];
		
		strcpy_s(szName, sizeof(szName), (LPCSTR)ps_segment_addr(exp,dwExportEntry));
		LPCSTR lpModuleName = szName;
		PCHAR pSep = strrchr(szName, '.');
		if (!pSep) return 0;
		*pSep = 0;
		LPCSTR lpFuncName = ++pSep;
		
		pe_t* fwdMod = ps_get_module(exp->pProcess, lpModuleName);
		if (!fwdMod) return 0;
		pe_export_t* fwdExp = export_load(exp->pProcess, fwdMod);
		//Forward by ordinal or name
		Addr = export_find_function(fwdExp, lpFuncName);
		export_unload(fwdExp);
	}
	return Addr;
}

ULONG_PTR export_find_function(pe_export_t* exp, LPCSTR lpName)
{
	if (lpName[0] == '#')
		return export_get_function(exp, (WORD)atoi(lpName + 1));

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		ps_directory(exp, IMAGE_DIRECTORY_ENTRY_EXPORT);
	PDWORD ppNameRVA = (PDWORD)ps_segment_addr(exp, pExport->AddressOfNames);
	PWORD pOrdinals = (PWORD)ps_segment_addr(exp, pExport->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		LPSTR lpFuncName = (LPSTR)ps_segment_addr(exp, ppNameRVA[i]);
		if (!strcmp(lpFuncName, lpName))
			return export_get_function(exp, (WORD)pExport->Base + pOrdinals[i]);
	}
	return 0;
}

static pe_reloc_t* reloc_init(ps_seg_t* dataSeg)
{
	if (dataSeg->pMod->pNt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		return NULL;
	PVOID lpReloc = ps_directory(dataSeg, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	pe_reloc_t* rel = (pe_reloc_t*)malloc(sizeof(pe_reloc_t));
	rel->pData = dataSeg;
	rel->pBlock = (PIMAGE_BASE_RELOCATION)lpReloc;
	rel->dwCurrentReloc = 0;

	return rel;
}

pe_reloc_t* reloc_load(process_t* ps, pe_t* mod)
{
	ps_seg_t* dataSeg = ps_load_directory(ps, mod, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (!dataSeg) return NULL;
	return reloc_init(dataSeg);
}

#define _relocs_count(size) ((size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD))

WORD reloc_next(pe_reloc_t* rel)
{
	if (rel->dwCurrentReloc == _relocs_count(rel->pBlock->SizeOfBlock))
	{
		rel->pBlock = (PIMAGE_BASE_RELOCATION)((PCHAR)rel->pBlock + rel->pBlock->SizeOfBlock);
		rel->dwCurrentReloc = 0;
	}

	if (rel->pBlock == (PIMAGE_BASE_RELOCATION)ps_directory_end(
		rel->pData, IMAGE_DIRECTORY_ENTRY_BASERELOC))
		return PS_NO_RELOC;

	return ((PWORD)((PCHAR)rel->pBlock + sizeof(IMAGE_BASE_RELOCATION)))[rel->dwCurrentReloc++];
}

void reloc_unload(pe_reloc_t* rel)
{
	ps_unload_segment(rel->pData);
	free(rel);
}

pe_import_t* import_load(process_t* ps, pe_t* mod)
{
	pe_import_t* imp = (pe_import_t*)malloc(sizeof(pe_import_t));
	imp->pImport = ps_load_directory(ps, mod, IMAGE_DIRECTORY_ENTRY_IMPORT);
	imp->pIAT = ps_load_directory(ps, mod, IMAGE_DIRECTORY_ENTRY_IAT);
	return imp;
}

BOOL import_find_thunk(pe_import_t* imp, ULONG_PTR ThunkAddr, PCHAR pszLibName, SIZE_T uLibNameLen,
	PCHAR pszFuncName, SIZE_T uFuncNameLen)
{
	PIMAGE_IMPORT_DESCRIPTOR pDesc = ps_directory(imp->pImport, IMAGE_DIRECTORY_ENTRY_IMPORT);
	while (pDesc->Characteristics)
	{
		PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)
			ps_segment_addr(imp->pImport, pDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
			ps_segment_addr(imp->pIAT, pDesc->FirstThunk);
		while (pOriginalThunk->u1.Function)
		{
			if ((ULONG_PTR)pThunk == ThunkAddr)
			{
				strcpy_s(pszLibName, uLibNameLen, (LPCSTR)
					ps_segment_addr(imp->pImport, pDesc->Name));
				if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
				{
					sprintf_s(pszFuncName, uFuncNameLen, "#%u", 
						IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)
						ps_segment_addr(imp->pImport, pOriginalThunk->u1.AddressOfData);
					strcpy_s(pszFuncName, uFuncNameLen, pName->Name);
				}
				return TRUE;
			}

			pOriginalThunk++;
			pThunk++;
		}

		pDesc++;
	}
	return FALSE;
}

void import_unload(pe_import_t* imp)
{
	ps_unload_segment(imp->pImport);
	ps_unload_segment(imp->pIAT);
	free(imp);
}
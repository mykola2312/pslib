#include "ps_image.h"

static DWORD _ps_section_flags[PS_IMAGE_SECTIONS] = {
	PAGE_EXECUTE_READ,
	PAGE_READWRITE,
	PAGE_READONLY
};

static DWORD _ps_image_vsec_init_size = PS_DEFAULT_RDATA_RSIZE;

static BOOL _ps_in_section(ULONG_PTR Base, PIMAGE_SECTION_HEADER pSection, ULONG_PTR Addr)
{
	ULONG_PTR Start = Base + pSection->VirtualAddress;
	ULONG_PTR End = Start + ps_section_size(pSection);
	return (Addr >= Start) && (Addr < End);
}

static INT _ps_determine_section(ULONG_PTR Base,PIMAGE_SECTION_HEADER* pHeaders, DWORD dwNum, ULONG_PTR Addr)
{
	for (DWORD i = 0; i < dwNum; i++)
	{
		ULONG_PTR Start = Base + pHeaders[i]->VirtualAddress;
		ULONG_PTR End = Start + ps_round_to_page(pHeaders[i]->SizeOfRawData);
		if (Addr >= Start && Addr < End)
			return (INT)i;
	}
	return -1;
}

ps_image_t* ps_image_create(pe_t* mod, ULONG_PTR VirtualBase,
	LPCSTR lpCodeSectionName, LPCSTR lpDataSectionName)
{
	PIMAGE_SECTION_HEADER pHeaders[PS_IMAGE_SECTIONS];

	pHeaders[PS_IMAGE_SECTION_CODE] = ps_get_section_header(mod, lpCodeSectionName);
	pHeaders[PS_IMAGE_SECTION_DATA] = ps_get_section_header(mod, lpDataSectionName);
	pHeaders[PS_IMAGE_SECTION_RDATA] = NULL;
	if (!pHeaders[PS_IMAGE_SECTION_CODE] || !pHeaders[PS_IMAGE_SECTION_DATA]) 
		return NULL;

	ps_image_t* image = (ps_image_t*)malloc(sizeof(ps_image_t));
	image->VirtualBase = VirtualBase;
	image->dwImports = 0;
	image->import = NULL;

	//Initialize sections
	image->dwVirtualSize = 0;
	for (DWORD i = 0; i < PS_IMAGE_SECTIONS; i++)
	{
		image->RSec[i].dwRealSize = pHeaders[i] 
			? pHeaders[i]->SizeOfRawData : _ps_image_vsec_init_size;
		image->RSec[i].pData = (PCHAR)malloc(image->RSec[i].dwRealSize);

		image->VSec[i].dwRVA = image->dwVirtualSize;
		image->VSec[i].dwSize = ps_round_to_page(image->RSec[i].dwRealSize);
		image->VSec[i].dwFlags = _ps_section_flags[i];

		if (pHeaders[i])
		{
			LPCVOID lpSource = (LPCVOID)(mod->BaseAddress + pHeaders[i]->VirtualAddress);
			CopyMemory(image->RSec[i].pData, lpSource, image->RSec[i].dwRealSize);
		}
		else ZeroMemory(image->RSec[i].pData, image->RSec[i].dwRealSize);

		image->dwVirtualSize += image->VSec[i].dwSize;
	}

	ULONG_PTR ModBase = mod->BaseAddress;

#ifndef _WIN64
	pe_reloc_t* rel = reloc_load(ps_this_process, mod);
	WORD wReloc;

	pe_import_t* imp = import_load(ps_this_process, mod);
	CHAR szLibName[64];
	CHAR szFuncName[64];

	while ((wReloc = reloc_next(rel)) != PS_NO_RELOC)
	{
		WORD wType = wReloc >> 12;
		ULONG_PTR RelocAddr = ModBase + (rel->pBlock->VirtualAddress | (wReloc & 0xFFF));
		if (wType != IMAGE_REL_BASED_HIGHLOW && wType != IMAGE_REL_BASED_DIR64)
			continue;
		INT iSrcSec = _ps_determine_section(ModBase, pHeaders, 2, RelocAddr);
		if (iSrcSec == -1) continue;
		
		PULONG_PTR DestAddr = (PULONG_PTR)(image->RSec[iSrcSec].pData +
			((RelocAddr - pHeaders[iSrcSec]->VirtualAddress) - ModBase));

		if (import_find_thunk(imp, *(PULONG_PTR)RelocAddr, szLibName, sizeof(szLibName),
			szFuncName, sizeof(szFuncName)))
		{
			ps_import_thunk_t* thunk = ps_image_import_add(image, szLibName, szFuncName);
			*DestAddr = image->VirtualBase + image->VSec[PS_IMAGE_SECTION_RDATA].dwRVA
				+ (thunk->dwIndex * sizeof(ULONG_PTR));
		}
		else
		{
			INT iDstSec = _ps_determine_section(ModBase, pHeaders, 2, *(PULONG_PTR)RelocAddr);
			if (iDstSec == -1) continue;

			*DestAddr = image->VirtualBase + image->VSec[iDstSec].dwRVA
				+ ((*(PULONG_PTR)RelocAddr - ModBase) - pHeaders[iDstSec]->VirtualAddress);
		}
	}
#endif

	reloc_unload(rel);
	import_unload(imp);

	return image;
}

//ps_image_import_add: Find or create thunk import
ps_import_thunk_t* ps_image_import_add(ps_image_t* image, LPCSTR lpLibName, LPCSTR lpFuncName)
{
	ps_import_lib_t* lib = NULL;
	ps_import_lib_t* lastLib = NULL;

	ps_import_thunk_t* thunk = NULL;
	ps_import_thunk_t* lastThunk = NULL;

	//Find or create ps_import_lib_t
	lastLib = image->import;
	while (lastLib)
	{
		SIZE_T uNameLen = strlen(lpLibName);
		if (!memcmp(lastLib->szLibName, lpLibName,
			min(uNameLen, sizeof(lastLib->szLibName))))
		{
			if (!lib) lib = lastLib;
		}
		if (!lastLib->next) break;
		else lastLib = lastLib->next;
	}

	if (!lib)
	{
		lib = (ps_import_lib_t*)malloc(sizeof(ps_import_lib_t));
		lib->thunk = NULL;
		lib->next = NULL;
		strcpy_s(lib->szLibName, sizeof(lib->szLibName), lpLibName);
		if (lastLib) lastLib->next = lib;
		else image->import = lib;
	}

	//Find or create ps_import_thunk_t
	lastThunk = lib->thunk;
	while (lastThunk)
	{
		SIZE_T uNameLen = strlen(lpFuncName);
		if (!memcmp(lastThunk->szFuncName, lpFuncName,
			min(uNameLen, sizeof(lastThunk->szFuncName))))
		{
			if (!thunk) thunk = lastThunk;
		}
		if (!lastThunk->next) break;
		else lastThunk = lastThunk->next;
	}

	if (!thunk)
	{
		thunk = (ps_import_thunk_t*)malloc(sizeof(ps_import_thunk_t));
		thunk->dwIndex = image->dwImports++;
		thunk->next = NULL;
		strcpy_s(thunk->szFuncName, sizeof(thunk->szFuncName), lpFuncName);
		if (lastThunk) lastThunk->next = thunk;
		else lib->thunk = thunk;
	}

	return thunk;
}

static void _ps_image_import_free(ps_import_lib_t* lib)
{
	ps_import_lib_t* libItem = lib;
	
	while (libItem)
	{
		ps_import_thunk_t* thunkItem = libItem->thunk;

		while (thunkItem)
		{
			ps_import_thunk_t* thunkNext = thunkItem->next;
			free(thunkItem);
			thunkItem = thunkNext;
		}

		ps_import_lib_t* libNext = libItem->next;
		free(libItem);
		libItem = libNext;
	}
}

void ps_image_free(ps_image_t* image)
{
	_ps_image_import_free(image->import);
	for (DWORD i = 0; i < PS_IMAGE_SECTIONS; i++)
		free(image->RSec[i].pData);
	free(image);
}
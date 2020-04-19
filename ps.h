#ifndef __PS_H
#define __PS_H

#include <Windows.h>

typedef struct {
	ULONG_PTR BaseAddress;
	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNt;
	CHAR szName[64];
} pe_t;

typedef struct {
	HANDLE hProcess;
	DWORD dwModules;
	pe_t* pModules;
	pe_t* pExe;
} process_t;

//For data or code. Segment of memory
typedef struct {
	process_t* pProcess;
	pe_t* pMod;
	//Segment info
	PCHAR pSeg;
	DWORD dwSegSize;
	DWORD dwSegRVA;
} ps_seg_t;

typedef ps_seg_t pe_export_t;

extern process_t* ps_this_process;
extern pe_t* ps_this_module;

extern DWORD ps_page_size;
extern DWORD ps_page_mask;
extern DWORD ps_page_power;

void ps_init();
void ps_exit();

DWORD ps_round_to_page(DWORD dwSize);

process_t* ps_load_process(DWORD dwPid);
void ps_unload_process(process_t* ps);

SIZE_T ps_read(process_t* ps, ULONG_PTR Addr, LPVOID lpDst, SIZE_T Size);
SIZE_T ps_write(process_t* ps, ULONG_PTR Addr, LPCVOID lpSrc, SIZE_T Size);

pe_t* ps_get_module(process_t* ps, LPCSTR lpModuleName);
ULONG_PTR ps_sig_scan(process_t* ps, pe_t* mod, LPCSTR lpSig, LPCSTR lpMask);

ps_seg_t* ps_load_segment(process_t* ps, pe_t* mod, ULONG_PTR Address, DWORD dwSize);
ps_seg_t* ps_load_directory(process_t* ps, pe_t* mod, UINT Dir);
void ps_unload_segment(ps_seg_t* seg);
#define ps_segment_addr(seg,rva) (PVOID)((PCHAR)seg->pSeg + rva - seg->dwSegRVA)
#define ps_directory(seg,dir) ps_segment_addr(seg,seg->pMod->pNt->OptionalHeader.DataDirectory[dir].VirtualAddress)
#define ps_directory_size(seg,dir) seg->pMod->pNt->OptionalHeader.DataDirectory[dir].Size
#define ps_directory_end(seg,dir) (PVOID)((PCHAR)ps_directory(seg,dir) + ps_directory_size(seg,dir))

PIMAGE_SECTION_HEADER ps_get_section_header(pe_t* mod, LPCSTR lpSectionName);
LPVOID ps_find_section(ps_seg_t* seg, LPCSTR lpSectionName);
DWORD ps_section_size(PIMAGE_SECTION_HEADER pSection);
BOOL ps_is_in_directory(pe_t* pe, UINT Dir, ULONG_PTR Addr);

#define ps_load_code(ps,mod) ps_load_segment_class(ps,mod,PS_SEG_CODE)
#define ps_unload_code ps_unload_segment
#define ps_load_data(ps,mod) ps_load_segment_class(ps,mod,PS_SEG_DATA)
#define ps_unload_data ps_unload_segment

#define ps_load_directory_segment(ps,mod,dir)								\
	ps_load_segment_class(ps,mod,ps_determine_directory_segment(mod,dir))	\

//#define export_load(ps,mod) ps_load_directory_segment(ps,mod,IMAGE_DIRECTORY_ENTRY_EXPORT)
#define export_load(ps,mod) ps_load_directory(ps,mod,IMAGE_DIRECTORY_ENTRY_EXPORT)
ULONG_PTR export_get_function(pe_export_t* exp, WORD wOrdinal);
ULONG_PTR export_find_function(pe_export_t* exp, LPCSTR lpName);
#define export_unload ps_unload_segment

typedef struct {
	ps_seg_t* pData;
	PIMAGE_BASE_RELOCATION pBlock;
	DWORD dwCurrentReloc;
} pe_reloc_t;

#define PS_NO_RELOC (WORD)-1

pe_reloc_t* reloc_load(process_t* ps, pe_t* mod);
WORD reloc_next(pe_reloc_t* rel);
void reloc_unload(pe_reloc_t* rel);

typedef struct {
	ps_seg_t* pImport;
	ps_seg_t* pIAT;
} pe_import_t;

pe_import_t* import_load(process_t* ps, pe_t* mod);
BOOL import_find_thunk(pe_import_t* imp, ULONG_PTR ThunkAddr, PCHAR pszLibName, SIZE_T uLibNameLen,
	PCHAR pszFuncName,SIZE_T uFuncNameLen);
void import_unload(pe_import_t* imp);

#endif
#ifndef __PS_IMAGE_H
#define __PS_IMAGE_H

#include "ps.h"

#define PS_DEFAULT_RDATA_RSIZE 4096
#define PS_DEFAULT_RDATA_VSIZE 4096

typedef struct {
	DWORD dwRVA;
	DWORD dwSize;
	DWORD dwFlags;
} ps_virtual_section_t;

typedef struct {
	PCHAR pData;
	DWORD dwRealSize;
} ps_real_section_t;

typedef enum {
	PS_IMAGE_SECTION_CODE = 0,	//For all program code
	PS_IMAGE_SECTION_DATA,		//For all program data
	PS_IMAGE_SECTION_RDATA,		//For all service data like IAT
	PS_IMAGE_SECTIONS
} ps_section_type;

typedef struct ps_import_thunk_s {
	CHAR szFuncName[64];
	DWORD dwIndex;	//Virtual IAT
	struct ps_import_thunk_s* next;
} ps_import_thunk_t;

typedef struct ps_import_lib_s {
	CHAR szLibName[64];
	ps_import_thunk_t* thunk;
	struct ps_import_lib_s* next;
} ps_import_lib_t;

typedef struct {
	//Virtual Image
	ULONG_PTR VirtualBase;
	DWORD dwVirtualSize;

	ps_real_section_t RSec[PS_IMAGE_SECTIONS];
	ps_virtual_section_t VSec[PS_IMAGE_SECTIONS];

	DWORD dwImports;	//Virtual IAT import count
	ps_import_lib_t* import;
} ps_image_t;

ps_image_t* ps_image_create(pe_t* mod,ULONG_PTR VirtualBase,
	LPCSTR lpCodeSectionName,LPCSTR lpDataSectionName);

ps_import_thunk_t* ps_image_import_add(ps_image_t* image, LPCSTR lpLibName, LPCSTR lpFuncName);

void ps_image_free(ps_image_t* image);

#endif
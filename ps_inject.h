#ifndef __PS_INJECT_H
#define __PS_INJECT_H

#include "ps.h"

#define PS_CREATE_IMAGE_FAILED -2
#define PS_NO_SECTIONS -1
#define PS_INJECT_OK 0

typedef struct {
	//Base of "image" in target process
	ULONG_PTR Base;
	DWORD dwSize;

	ULONG_PTR CodeVA;
	DWORD dwCodeSize;

	ULONG_PTR DataVA;
	DWORD dwDataSize;

	ULONG_PTR EntryPointVA;
} ps_inject_t;

int ps_inject(process_t* ps, pe_t* thisMod, LPCSTR lpCodeSec, LPCSTR lpDataSec,
	LPVOID lpEntryPoint,ps_inject_t* inject);

BOOL ps_adjust_privilege(LPCSTR lpPrivilegeName);
BOOL ps_hijack_thread(process_t* ps, DWORD dwTid, ULONG_PTR Code);

#endif
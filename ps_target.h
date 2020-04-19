#ifndef __PS_TARGET_H
#define __PS_TARGET_H

#include <Windows.h>

#ifndef _WIN64

#define PS_IMPORT(funcName,thunkName)		\
	__declspec(naked) ULONG_PTR thunkName()	\
	{										\
		__asm jmp dword ptr ds : [funcName]	\
	}

#endif

#endif
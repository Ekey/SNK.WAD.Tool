#include <stdafx.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "lz4.h"

extern "C"
{
__declspec(dllexport) void __stdcall SNK_Decompress(unsigned char* lpSrcBuffer, unsigned char* lpDstBuffer, int dwSize)
{
	LZ4_decompress_fast((const char*)lpSrcBuffer, (char*)lpDstBuffer, dwSize);
 }
}
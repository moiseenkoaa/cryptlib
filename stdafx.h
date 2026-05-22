// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

//#pragma once


#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

// TODO: reference additional headers your program requires here

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include "ToolsLib\ToolsLib.h"
#endif
#ifdef __unix__
#include "ToolsLib/ToolsLib.h"
#endif

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>

#pragma warning( disable : 4996 ) // warning C4996: 'sprintf': This function or variable may be unsafe. Consider using sprintf_s instead. To disable deprecation, use _CRT_SECURE_NO_DEPRECATE. See online help for details.
//#pragma warning( disable : 4996 ) // warning C4996: 'strcpy': This function or variable may be unsafe. Consider using strcpy_s instead. To disable deprecation, use _CRT_SECURE_NO_DEPRECATE. See online help for details.


#endif

#include "Definitions.h"

static ULONG		gGamePid = 0;
static DWORD64		gKernelBase = NULL;
static DWORD64		gBaseAddress = NULL;
static PEPROCESS	gGameProcess = NULL;
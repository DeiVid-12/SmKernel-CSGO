#pragma once
#include "CSharedMemory.h"

class CMemory {
public:
	static NTSTATUS Read(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
	static NTSTATUS Write(PEPROCESS ProcessOfTarget, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size, KM_WRITE_REQUEST* pdata);
	static NTSTATUS GetPid(void);
	static NTSTATUS GetImageBase(PEPROCESS Process);
	static NTSTATUS GetGameHandle();
	static DWORD GetModuleBasex64(PEPROCESS Process, UNICODE_STRING ModuleName);
};


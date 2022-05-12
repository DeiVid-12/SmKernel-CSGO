#pragma once
#include <tchar.h>
#include <windows.h>
#include <iostream>
#include <accctrl.h>
#include <aclapi.h>
#define Log(x) printf(x)

static ULONG PID;
static ULONG64 BaseAddress = NULL;
static HANDLE hMapFileW;
static HANDLE hMapFileR;
static HANDLE g_hMutex;

static HANDLE SharedEventDataArv;
static HANDLE SharedEventTrigger;
static HANDLE SharedEventReady2Read;

static DWORD dwRes;
static SECURITY_ATTRIBUTES sa;
static PSECURITY_DESCRIPTOR pSD = NULL;
static SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
static PACL pAcl = NULL;
static PSID pEveryoneSID = NULL;
static EXPLICIT_ACCESS ea[1];


typedef struct _KM_READ_REQUEST
{
	ULONG ProcessId;
	UINT_PTR SourceAddress;
	ULONGLONG Size;
	void* Output;

} KM_READ_REQUEST;


typedef struct _KM_WRITE_REQUEST
{
	ULONG ProcessId;
	ULONG ProcessidOfSource;
	UINT_PTR SourceAddress;
	UINT_PTR TargetAddress;
	ULONGLONG Size;
} KM_WRITE_REQUEST;


typedef struct _GET_USERMODULE_IN_PROCESS
{
	ULONG pid;
	ULONG64 BaseAddress;
} GET_USERMODULE_IN_PROCESS;




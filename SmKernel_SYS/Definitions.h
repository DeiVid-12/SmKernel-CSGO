#pragma once
#include <ntifs.h>
#include <windef.h>
#define _DEBUG

#ifdef _DEBUG
#define Log(x) DbgPrintEx(0, 0, x);
#else
#define Log(x)
#endif // _DEBUG

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

const WCHAR SharedSectionName[] = L"\\BaseNamedObjects\\ShKernel"; //Allocate buffer for name of shared memory


static PVOID	pSharedSection = NULL;
static PVOID	pSectionObj = NULL;
static HANDLE	hSection = NULL;

static SECURITY_DESCRIPTOR SecDescriptor;
static HANDLE sectionHandle;
static PVOID	SharedSection = NULL;
static PVOID	Sharedoutputvar = NULL;
static ULONG DaclLength;
static PACL Dacl; // this is the problem i guess PACL


// trigger loop
static HANDLE  SharedEventHandle_trigger = NULL;
static PKEVENT SharedEvent_trigger = NULL;
static UNICODE_STRING EventName_trigger;


// ReadyRead
static HANDLE  SharedEventHandle_ReadyRead = NULL;
static PKEVENT SharedEvent_ReadyRead = NULL;
static UNICODE_STRING EventName_ReadyRead;

// data arrived
static HANDLE  SharedEventHandle_dt = NULL;
static PKEVENT SharedEvent_dt = NULL;
static  UNICODE_STRING EventName_dt;


typedef struct _KM_READ_REQUEST
{
	ULONG ProcessId;
	UINT_PTR SourceAddress;
	ULONGLONG Size;
	void* Output;

} KM_READ_REQUEST;

// write struct
typedef struct _KM_WRITE_REQUEST
{
	ULONG ProcessId;
	ULONG ProcessidOfSource;
	UINT_PTR SourceAddress;
	UINT_PTR TargetAddress;
	ULONGLONG Size;

} KM_WRITE_REQUEST;

// get module struct
typedef struct _GET_USERMODULE_IN_PROCESS
{
	ULONG pid;
	ULONG64 BaseAddress;
} GET_USERMODULE_IN_PROCESS;



EXTERN_C NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);



EXTERN_C
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	IN HANDLE ProcessId,
	OUT PEPROCESS* Process
);


EXTERN_C
NTKERNELAPI
PPEB
PsGetProcessPeb(
	IN PEPROCESS Process
);

EXTERN_C
NTKERNELAPI
PVOID 
PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);


EXTERN_C NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);


typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported



typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	IN  PULONG ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;
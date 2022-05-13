#include "CMemory.h"
#include "Globals.h"


NTSTATUS CMemory::Read(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
	PSIZE_T Bytes;
	NTSTATUS ntStatus = STATUS_SUCCESS;

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)Process, &state);
	Log("[SmKernel]Calling MmCopyVirtualMemory... \n");
	MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, (PSIZE_T)&Bytes);
	KeUnstackDetachProcess(&state);

	if (!NT_SUCCESS(ntStatus)) {
		Log("[SmKernel]Error Code... %x\n", status);
		Log("[SmKernel]__MmCopyVirtualMemory Error || Process : %p || SourceAddress : %p || PsGetCurrentProcess() : %p || TargetAddress : %p || Size : %x  Bytes : %x \n", Process, SourceAddress, PsGetCurrentProcess, TargetAddress, Size, Bytes);
		return ntStatus;
	}
	else {
		Log("[SmKernel]MmCopyVirtualMemory Success! %x\n", status);
		Log("[SmKernel]Bytes Read : %u \n", Bytes);
	}
}

NTSTATUS CMemory::Write(PEPROCESS ProcessOfTarget, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size, KM_WRITE_REQUEST* pdata) {
	PSIZE_T Bytes;
	NTSTATUS ntStaus = STATUS_SUCCESS;

	Log("[SmKernel]ProcessidOfSource : %u \n", pdata->ProcessidOfSource);

	PEPROCESS ProcessOfSource;
	ntStaus = PsLookupProcessByProcessId((HANDLE)pdata->ProcessidOfSource, &ProcessOfSource);
	if (NT_SUCCESS(ntStaus)) {
		Log("[SmKernel]PsLookupProcessByProcessId has success ProcessOfSource address : %p \n", ProcessOfSource);
	}
	else {
		ntStaus = STATUS_ACCESS_DENIED;
		ObDereferenceObject(ProcessOfSource);
		Log("[SmKernel]PsLookupProcessByProcessId Failed Error code : %p \n", ntStaus);
		return ntStaus;
	}

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)ProcessOfSource, &state);
	Log("[SmKernel]Calling MmCopyVirtualMemory withtin the source context. \n");
	ntStaus = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, ProcessOfTarget, TargetAddress, Size, KernelMode, (PSIZE_T)&Bytes);
	KeUnstackDetachProcess(&state);


	if (!NT_SUCCESS(ntStaus)) {
		Log("[SmKernel]Error Code... %x\n", ntStaus);
		Log("[SmKernel]MmCopyVirtualMemory_Error =  PsGetCurrentProcess : %p SourceAddress : %p ProcessOfTarget : %p TargetAddress :  %p Size : %x Bytes : %x \n", PsGetCurrentProcess(), SourceAddress, ProcessOfTarget, TargetAddress, Size, Bytes);
	}
	else {
		Log("[SmKernel]MmCopyVirtualMemory Success! %x\n", status);
		Log("[SmKernel]Bytes : %x \n", Bytes);
	}
}

NTSTATUS CMemory::GetPid(void) {
	ULONG CallBackLength = 0;
	PSYSTEM_PROCESS_INFO PSI = NULL;
	PSYSTEM_PROCESS_INFO pCurrent = NULL;
	PVOID BufferPid = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	// Names
	PCWSTR ProcName = L"csgo.exe";
	UNICODE_STRING uImageName;
	RtlInitUnicodeString(&uImageName, ProcName);

	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &CallBackLength))) {
		BufferPid = ExAllocatePoolWithTag(NonPagedPool, CallBackLength, 0x616b7963); // aykc 
		if (!BufferPid) {
			Log("[SmKernel]Failed To Allocate Buffer Notify Routine");
			return ntStatus;
		}

		PSI = (PSYSTEM_PROCESS_INFO)BufferPid;
		ntStatus = ZwQuerySystemInformation(SystemProcessInformation, PSI, CallBackLength, NULL);
		if (!NT_SUCCESS(ntStatus)) {
			Log("[SmKernel]Failed To Get Query System Process Information List: %p", ntStatus);
			ExFreePoolWithTag(BufferPid, 0x616b7963);
			return ntStatus = STATUS_INFO_LENGTH_MISMATCH;
		}

		do {
			if (PSI->NextEntryOffset == 0)
				break;

			if (RtlEqualUnicodeString(&uImageName, &PSI->ImageName, FALSE)) {
				DbgPrintEx(0, 0, "PID %d | NAME %ws", PSI->ProcessId, PSI->ImageName.Buffer);
				gGamePid = (ULONG)PSI->ProcessId;
				ntStatus = STATUS_SUCCESS;
				break;
			}

			PSI = (PSYSTEM_PROCESS_INFO)((unsigned char*)PSI + PSI->NextEntryOffset);
		} while (PSI->NextEntryOffset);

		// Free Allocated Memory
		ExFreePoolWithTag(BufferPid, 0x616b7963);
	}

	return ntStatus;
}

DWORD CMemory::GetModuleBasex64(PEPROCESS Process, UNICODE_STRING ModuleName) {
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb) {
		Log("[SmKernel]Error pPeb not found \n");
		return 0; 
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		DbgPrintEx(0, 0, "Error pLdr not found \n");
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}



	// loop the linked list
	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
		list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry =
			CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
			0) {
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}
	DbgPrintEx(0, 0, "Error exiting funcion nothing was found found \n");
	KeUnstackDetachProcess(&state);

	return 0;
}

NTSTATUS CMemory::GetImageBase(PEPROCESS Process) {
	KAPC_STATE State;

	KeStackAttachProcess(Process, &State);
	gBaseAddress = (DWORD64)(DWORD64*)PsGetProcessSectionBaseAddress(Process);
	KeUnstackDetachProcess(&State);

	Log("[SmKernel]Image Found:%p\n", gBaseAddress);

	return STATUS_SUCCESS;
}

NTSTATUS CMemory::GetGameHandle() {
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	if (gGamePid) {
		ntStatus = PsLookupProcessByProcessId((HANDLE)gGamePid, &gGameProcess);
		if (!NT_SUCCESS(ntStatus)) {
			Log("[SmKernel]PsLookupProcessByProcessId Failed (game PID): %p\n", ntStatus);
			return ntStatus;
		}
	}
	return ntStatus;
}

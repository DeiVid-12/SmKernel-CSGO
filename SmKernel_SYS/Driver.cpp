#include "CMemory.h"
#include "Globals.h"

NTSTATUS Init(void)  {
	NTSTATUS ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString(&EventName_dt, L"\\BaseNamedObjects\\DataArrived");
	SharedEvent_dt = IoCreateNotificationEvent(&EventName_dt, &SharedEventHandle_dt);
	if (SharedEvent_dt == NULL) {
		Log("[SmKernel]Error! \n", ntStatus);
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&EventName_trigger, L"\\BaseNamedObjects\\trigger");
	SharedEvent_trigger = IoCreateNotificationEvent(&EventName_trigger, &SharedEventHandle_trigger);
	if (SharedEvent_trigger == NULL) {
		Log("[SmKernel]Error! \n", ntStatus);
		return STATUS_UNSUCCESSFUL;
	}


	RtlInitUnicodeString(&EventName_ReadyRead, L"\\BaseNamedObjects\\ReadyRead");
	SharedEvent_ReadyRead = IoCreateNotificationEvent(&EventName_ReadyRead, &SharedEventHandle_ReadyRead);
	if (SharedEvent_ReadyRead == NULL) {
		Log("[SmKernel]Error! \n", ntStatus);
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS DriverLoop(void) {
	while (true) {
		Log("[SmKernel]Waitting for command...")
		CSharedMemory::Read();
		if (strcmp((PCHAR)SharedSection, "Stop") == 0) {
			Log("[SmKernel]Stoping...\n");
			break;
		}

		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "Write") == 0) {
			Log("[SmKernel]Writing memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			CSharedMemory::Read();


			KM_WRITE_REQUEST* WriteInput = (KM_WRITE_REQUEST*)SharedSection;
			PEPROCESS Process;
			NTSTATUS ntStatus = STATUS_SUCCESS;

			ntStatus = PsLookupProcessByProcessId((HANDLE)WriteInput->ProcessId, &Process);
			if (NT_SUCCESS(ntStatus)) {
				Log("[SmKernel]PsLookupProcessByProcessId has success! : %p \n", ntStatus);
				Log("[SmKernel]Writing memory.\n");
				CMemory::Write(Process, (PVOID)WriteInput->SourceAddress, (PVOID)WriteInput->TargetAddress, WriteInput->Size, WriteInput);
			}
			else {
				ntStatus = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				Log("[SmKernel]PsLookupProcessByProcessId Failed Error code : %p \n", ntStatus);
				return ntStatus;
			}

			KeResetEvent(SharedEvent_dt);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "Read") == 0) {
			Log("[SmKernel]Read memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);


			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			CSharedMemory::Read();


			KM_READ_REQUEST* ReadInput = (KM_READ_REQUEST*)SharedSection;
			void* ReadOutput = NULL;
			PEPROCESS Process;
			NTSTATUS Status = STATUS_SUCCESS;

			Log("[SmKernel]ReadInput : %p PID : %u SourceAddress : %p ReadOutput : %p Size : %x \n", ReadInput, ReadInput->ProcessId, ReadInput->SourceAddress, ReadOutput, ReadInput->Size);
			Log("[SmKernel](Before mmcopyvirtualmemory) ReadOutput : %p \n", ReadOutput);

			Status = PsLookupProcessByProcessId((PVOID)ReadInput->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				Log("[SmKernel]PsLookupProcessByProcessId has success! : %p \n", Status);
				Log("[SmKernel]ReadKernelMemory will be called now !.\n");
				CMemory::Read(Process, (PVOID)ReadInput->SourceAddress, &ReadOutput, ReadInput->Size);
			}
			else {
				Status = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				Log("[SmKernel]PsLookupProcessByProcessId Failed Error code : %p \n", Status);
				return Status;
			}

			ReadInput->Output = ReadOutput;

			CSharedMemory::Read();
			if (0 == memcpy(SharedSection, ReadInput, sizeof(KM_READ_REQUEST))) {
				Log("[SmKernel]memcpy failed \n");
			}


			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "getBase") == 0) {
			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			CSharedMemory::Read();


			GET_USERMODULE_IN_PROCESS* GetBase = (GET_USERMODULE_IN_PROCESS*)SharedSection;

			NTSTATUS ntStatus = STATUS_SUCCESS;
			PEPROCESS TargetProcess;
			ntStatus = PsLookupProcessByProcessId((HANDLE)GetBase->pid, &TargetProcess);
			if (!NT_SUCCESS(ntStatus)) {
				Log("[SmKernel]PsLookupProcessByProcessId failed\n");
			}
			Log("[SmKernel]PsLookupProcessByProcessId Success!\n");

			UNICODE_STRING DLLName;
			RtlInitUnicodeString(&DLLName, L"client.dll");
			GetBase->BaseAddress = CMemory::GetModuleBasex64(TargetProcess, DLLName);


			Log("[SmKernel]GetBase->BaseAddress is : %p \n", GetBase->BaseAddress);

			CSharedMemory::Read();

			if (0 == memcpy(SharedSection, GetBase, sizeof(GET_USERMODULE_IN_PROCESS))) {
				Log("[SmKernel]memcpy failed \n");
			}

			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
		}
	}
}

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	Log("[SmKernel]Driver Unloaded!");

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	if (sectionHandle)
		ZwClose(sectionHandle);

	Log("[SmKernel]DriverUnload complete!");
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)  {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(pRegistryPath);


	Log("[SmKernel]Driver loaded !!\n");

	pDriverObject->DriverUnload = DriverUnload;

	CSharedMemory::Create();

	Init();

	DriverLoop();

	Log("[SmKernel]Driver entry completed!\n");

	return STATUS_SUCCESS;
}

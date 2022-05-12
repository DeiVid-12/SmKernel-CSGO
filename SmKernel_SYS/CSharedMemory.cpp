#include "CSharedMemory.h"

NTSTATUS CSharedMemory::Create(void)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ntStatus = RtlCreateSecurityDescriptor(&SecDescriptor, SECURITY_DESCRIPTOR_REVISION);

    if (!NT_SUCCESS(ntStatus)) {
        Log("[SmKernel]RtlCreateSecurityDescriptor failed : %p\n", ntStatus);
        return ntStatus;
    }
    // Get length
    DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid) +
        RtlLengthSid(SeExports->SeWorldSid);


    // Allocate memory
    Dacl = (PACL)ExAllocatePoolWithTag(PagedPool, DaclLength, 'smkC');

    if (Dacl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
        Log("[SmKernel]RExAllocatePoolWithTag  failed  : %p\n", ntStatus);
    }
    ntStatus = RtlCreateAcl(Dacl, DaclLength, ACL_REVISION);

    if (!NT_SUCCESS(ntStatus)) {
        ExFreePool(Dacl);
        Log("[SmKernel]RtlCreateAcl  failed  : %p\n", ntStatus);
        return ntStatus;
    }
    ntStatus = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

    if (!NT_SUCCESS(ntStatus)) {
        ExFreePool(Dacl);
        Log("[SmKernel]RtlAddAccessAllowedAce SeWorldSid failed  : %p\n", ntStatus);
        return ntStatus;
    }

	ntStatus = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeAliasAdminsSid);

	if (!NT_SUCCESS(ntStatus)) {
		ExFreePool(Dacl);
		Log("[SmKernel]RtlAddAccessAllowedAce SeAliasAdminsSid failed  : %p\n", ntStatus);
		return ntStatus;
	}

	ntStatus = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeLocalSystemSid);

	if (!NT_SUCCESS(ntStatus)) {
		ExFreePool(Dacl);
		Log("[SmKernel]RtlAddAccessAllowedAce SeLocalSystemSid failed  : %p\n", ntStatus);
		return ntStatus;
	}

	ntStatus = RtlSetDaclSecurityDescriptor(&SecDescriptor,
		TRUE,
		Dacl,
		FALSE);

	if (!NT_SUCCESS(ntStatus)) {
		ExFreePool(Dacl);
		Log("[SmKernel]RtlSetDaclSecurityDescriptor failed  : %p\n", ntStatus);
		return ntStatus;
	}

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, SharedSectionName);
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &SecDescriptor);

	if (!NT_SUCCESS(ntStatus)) {
		Log("[SmKernel]Last thing  has failed : %p\n", ntStatus);
	}

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	ntStatus = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL); 
	if (!NT_SUCCESS(ntStatus)) {
		Log("[SmKernel]ZwCreateSection failed: %p\n", ntStatus);
		return ntStatus;
	}
	
	SIZE_T ulViewSize = 1024 * 10; 
	ntStatus = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(ntStatus)) {
		Log("[SmKernel]ZwMapViewOfSection fail! Status: %p\n", ntStatus);
		ZwClose(sectionHandle);
		return ntStatus;
	}

	Log("[SmKernel]CreateSharedMemory called finished \n");

	ExFreePool(Dacl); 

	return ntStatus;
}

void CSharedMemory::Read(void)
{
	if (sectionHandle)
		return;

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	SIZE_T ulViewSize = 1024 * 10;
	NTSTATUS ntStatus = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (ntStatus != STATUS_SUCCESS) {
		Log("[SmKernel]ZwMapViewOfSection fail! Status: %p\n", ntStatus);
		ZwClose(sectionHandle);
		return;
	}
}
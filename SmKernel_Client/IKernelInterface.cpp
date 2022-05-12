#include "IKernelInterface.h"
#include <TlHelp32.h>

DWORD_PTR IKernelInterface::CMemory::FindProcessId(const std::string& processName) {
	// TODO: Implemente this function ok kernel
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile)) {
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo)) {
		if (!processName.compare(processInfo.szExeFile)) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

bool IKernelInterface::CMemory::WriteVirtualMemory(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize) {
	auto WriteMemoryMsg = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
	char str[8];
	// str to driver read
	strcpy_s(str, "Write");
	// Coping to memory
	RtlCopyMemory(WriteMemoryMsg, str, strlen(str) + 1);

	UnmapViewOfFile(WriteMemoryMsg);

	WaitForSingleObject(SharedEventDataArv, INFINITE);

	KM_WRITE_REQUEST* SentStruct = (KM_WRITE_REQUEST*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(KM_WRITE_REQUEST));

	if (!SentStruct) {
		Log("Error MapViewOfFile!\r\n");
		return false;
	}
	// Setting up instructions
	KM_WRITE_REQUEST  WriteRequest;
	WriteRequest.ProcessId = PID;
	WriteRequest.ProcessidOfSource = GetCurrentProcessId();
	WriteRequest.TargetAddress = WriteAddress;
	WriteRequest.SourceAddress = SourceAddress;
	WriteRequest.Size = WriteSize;

	KM_WRITE_REQUEST* ptr = &WriteRequest;
	if (0 == memcpy(SentStruct, ptr, sizeof(KM_WRITE_REQUEST))) {
		Log("Error copying memory with (memcpy) to struct\n");
		return false;
	}

	// success
	Log("%p\n", SentStruct);
	UnmapViewOfFile(SentStruct);

	// Wait for kernel signal before exit
	WaitForSingleObject(SharedEventTrigger, INFINITE);
	ResetEvent(SharedEventTrigger);
	return true;
}

ULONG64 IKernelInterface::CMemory::GetModuleBase(ULONG pid) {
	auto MapViewMsg = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
	if (!MapViewMsg) {
	Log("MapViewMsg Failed. Func - Request ");
		return false;
	}
	char Msg[8];
	strcpy_s(Msg, "getBase");

	// Copy Memory Over To Map
	RtlCopyMemory(MapViewMsg, Msg, strlen(Msg) + 1);
	UnmapViewOfFile(MapViewMsg);

	WaitForSingleObject(SharedEventDataArv, INFINITE);

	GET_USERMODULE_IN_PROCESS* SentStruct = (GET_USERMODULE_IN_PROCESS*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(GET_USERMODULE_IN_PROCESS));
	
	if (!SentStruct) {
		Log("Error MapViewOfFile(SentStruct)\n");
		return 0;
	}


	GET_USERMODULE_IN_PROCESS requestbase;

	requestbase.pid = pid;

	GET_USERMODULE_IN_PROCESS* ptr = &requestbase;
	if (0 == memcpy(SentStruct, ptr, sizeof(GET_USERMODULE_IN_PROCESS))) {
		Log("Error copying memory with (memcpy) to struct\n");
		return 0;
	}
	Log("PID : %u \n", requestbase.pid);

	UnmapViewOfFile(SentStruct);


	WaitForSingleObject(SharedEventReady2Read, INFINITE);

	GET_USERMODULE_IN_PROCESS* GetBaseStruct = (GET_USERMODULE_IN_PROCESS*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, sizeof(GET_USERMODULE_IN_PROCESS));
	if (!GetBaseStruct) {
		Log("OpenFileMappingA(getbase_struct) fail! Error: %u\n", GetLastError());
		return 0;
	}
	ULONG64 base = NULL;

	base = GetBaseStruct->BaseAddress;

	Log("Base address of dummy program : %p \n", GetBaseStruct->BaseAddress);
	Log("Base  : %p \n", base);

	UnmapViewOfFile(GetBaseStruct);

	return base;
}

void IKernelInterface::CMemory::GetPidAndModuleBase(void) {
	PID = FindProcessId("csgo.exe");
	std::cout << "PID IS : " << PID << std::endl;

	// get base address
	BaseAddress = GetModuleBase(PID);
	std::cout << "base address is : " << std::hex << BaseAddress << std::endl;
}

void IKernelInterface::CSharedMemory::CreateSecuritydescriptor(void) {
	if (!AllocateAndInitializeSid(
		&SIDAuthWorld,   //PSID_IDENTIFIER_AUTHORITY
		1,               //nSubAuthorityCount
		SECURITY_WORLD_RID,     //nSubAuthority0
		0, 0, 0, 0, 0, 0, 0,    //Not used subAuthorities.
		&pEveryoneSID))         //Callback argument that recieves pointer to the allocated and initialized SID structure
	{
		Log("AllocateAndInitializeSid() Error.\n", GetLastError());
		system("pause");
	}


	//Filling in EXPLICIT_ACCESS structure. Everyone's group members will have all the permissions on event.
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	//ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	//Creation of new ACL that contains the new ACE.
	dwRes = SetEntriesInAcl(1, ea, NULL, &pAcl);
	if (dwRes != ERROR_SUCCESS) {
		Log("SetEntriesInAcl() Error.\n", GetLastError());
		system("pause");
	}
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (pSD == NULL) {
		Log("LocalAlloc() Error.\n", GetLastError());
		system("pause");
	}
	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
		Log("InitializeSecurityDescriptor() Error.\n", GetLastError());
		system("pause");
	}
	//Adding ACL to Security Descriptor.
	if (!SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE)) {
		Log("SetSecurityDescriptorDacl() Error.\n", GetLastError());
		system("pause");
	}
	//Initialize Security Attributes structure.
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;
}

void IKernelInterface::CSharedMemory::Create(void) {
	SharedEventDataArv = CreateEventA(&sa, TRUE, FALSE, "GlobalsDataArrived");
	if (!SharedEventDataArv) {
		Log("SharedEventDataArv CreateEventA fail! Error: %u\n", GetLastError());
		system("pause");
	}
	Log("CreateEventA SUCESS (SharedEvent->(DataArrived)) ! \n");

	SharedEventTrigger = CreateEventA(&sa, TRUE, FALSE, "Global\\trigger");
	if (!SharedEventTrigger) {
		Log("SharedEventTrigger CreateEventA fail! Error: %u\n", GetLastError());
		system("pause");
	}
	Log("CreateEventA SUCESS (SharedEvent->(trigger)) ! \n");

	SharedEventReady2Read = CreateEventA(&sa, TRUE, FALSE, "Global\\ReadyRead");
	if (!SharedEventReady2Read) {
		Log("SharedEventReady2Read CreateEventA fail! Error: %u\n", GetLastError());
		system("pause");
	}
	Log("CreateEventA SUCESS (SharedEvent->(ready2read)) ! \n");
}

bool IKernelInterface::CSharedMemory::Open(void) {
	hMapFileW = OpenFileMappingA(FILE_MAP_WRITE, FALSE, "Global\\SharedMem");
	if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE) {
		Log("OpenFileMappingA(write) fail! Error: %u\n", GetLastError());
		return false;
	}
	hMapFileR = OpenFileMappingA(FILE_MAP_READ, FALSE, "Global\\SharedMem");
	if (!hMapFileR || hMapFileR == INVALID_HANDLE_VALUE) {
		Log("OpenFileMappingA(read) fail! Error: %u\n", GetLastError());
		return false;
	}
	Log("Shared memory opened\n");
	return true;
}

void IKernelInterface::CSharedMemory::Stop(void) {
	auto StopMsg = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);

	char stopmms[8];
	strcpy_s(stopmms, "Stop");


	RtlCopyMemory(StopMsg, stopmms, strlen(stopmms) + 1);

	Log("message has been sent to kernel [Stop]! \n");


	FlushViewOfFile(StopMsg, 4096);
	UnmapViewOfFile(StopMsg);
}

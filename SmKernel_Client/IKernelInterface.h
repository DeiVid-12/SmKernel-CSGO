#pragma once
#include "Definitions.h"

// Driver Interface
namespace IKernelInterface {

	class CMemory {
	public:
		DWORD_PTR FindProcessId(const std::string& processName);

		template<typename T>
		bool Write(UINT_PTR WriteAddress, const T& value);

		bool WriteVirtualMemory(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize);
		template <typename type>
		type Read(UINT_PTR ReadAddress);

		ULONG64 GetModuleBase(ULONG pid);

		void GetPidAndModuleBase(void);
	};

	class CSharedMemory {
	public:
		void CreateSecuritydescriptor(void);
		void Create(void);
		bool Open(void);
		void Stop(void);
	};
}

template<typename T>
inline bool IKernelInterface::CMemory::Write(UINT_PTR WriteAddress, const T& value)
{
	return WriteVirtualMemoryRaw(WriteAddress, (UINT_PTR)&value, sizeof(T));
}

template<typename type>
inline type IKernelInterface::CMemory::Read(UINT_PTR ReadAddress)
{
	auto ReadMemory = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
	char str[8];
	strcpy_s(str, "Read");
	RtlCopyMemory(ReadMemory, str, strlen(str) + 1);

	UnmapViewOfFile(ReadMemory);

	WaitForSingleObject(SharedEventDataArv, INFINITE);


	KM_READ_REQUEST* SentStruct = (KM_READ_REQUEST*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(KM_READ_REQUEST));

	if (!SentStruct) {
		Log("Error MapViewOfFile(Sent_struct)\n");
		return false;
	}

	KM_READ_REQUEST ReadRequest{};

	// just to clairfy this is like doing for ex : int response; its an empty var
	type response{};

	ReadRequest.ProcessId = PID;
	ReadRequest.SourceAddress = ReadAddress;
	ReadRequest.Size = sizeof(type);
	ReadRequest.Output = &response;


	KM_READ_REQUEST* ptr = &ReadRequest;
	if (0 == memcpy(SentStruct, ptr, sizeof(KM_READ_REQUEST))) {
		Log("Error copying memory with (memcpy) to struct\n");
		return -1;
	}	
	Log("Struct pointer : %p PID : %u ReadAddress : %p Output : %p Size : %x \n", SentStruct, ReadRequest.ProcessId, ReadRequest.SourceAddress, ReadRequest.Output, ReadRequest.Size);
	UnmapViewOfFile(SentStruct);

	WaitForSingleObject(SharedEventReady2Read, INFINITE);

	KM_READ_REQUEST* ReadStruct = (KM_READ_REQUEST*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, sizeof(KM_READ_REQUEST));
	if (!ReadStruct) {
		Log("OpenFileMappingA(Read_struct) fail! Error: %u\n", GetLastError());
		return -1;
	}

	Log("Data Read_struct : %p\n", Read_struct);
	Log("Data Read_struct->Output : %p\n", Read_struct->Output);
	Log("Data value : %u \n", Read_struct->Output);

	type ReturnVal = ((type)ReadStruct->Output);

	UnmapViewOfFile(ReadStruct);
	WaitForSingleObject(SharedEventTrigger, INFINITE);
	ResetEvent(SharedEventTrigger);
	return ReturnVal;
}

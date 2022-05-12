#include "CFunctions.h"

CFunctions functions;
IKernelInterface::CSharedMemory* SharedMemory;
IKernelInterface::CMemory* Memory;

int _tmain(void)
{
	int nCode = 0;

	Memory->GetPidAndModuleBase();

	SharedMemory->CreateSecuritydescriptor();
	
	SharedMemory->Create();

	nCode = SharedMemory->Open();
	if (!nCode) {
		Log("Fail to open shared memory!");
		return nCode;
	}
	Sleep(1000);

	system("cls");
	Log("Started, press f4 to stop");

	// TODO: Make a thread 
	while (!GetAsyncKeyState(VK_F4)) {
		functions.TriggerBot(60, VK_RBUTTON);
		Sleep(25);
	}
	SharedMemory->Stop();

	return nCode;
}
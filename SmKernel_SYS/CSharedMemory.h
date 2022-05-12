#pragma once
#include "Definitions.h"
class CSharedMemory {
public:
	static NTSTATUS Create(void);
	static void Read(void);
};


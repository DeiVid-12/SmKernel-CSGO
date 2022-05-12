#include "Offsets.h"
#include "IKernelInterface.h"

using namespace hazedumper;
using namespace hazedumper::signatures;
using namespace hazedumper::netvars;

class CFunctions {
private:
	uintptr_t GetLocalPlayer(void);
	uintptr_t GetPlayer(int index);
	int GetTeam(uintptr_t player);
	int GetCrosshairID(uintptr_t player);
public:
	void TriggerBot(int delay, int key);
};
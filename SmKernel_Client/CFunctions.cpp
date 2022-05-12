#include "CFunctions.h"

IKernelInterface::CMemory* Mem;

uintptr_t CFunctions::GetLocalPlayer(void)
{
    return Mem->Read<uintptr_t>(BaseAddress + dwLocalPlayer);
}

uintptr_t CFunctions::GetPlayer(int index)
{
    return Mem->Read<uintptr_t>(BaseAddress + dwEntityList + index * 0x10);
}

int CFunctions::GetTeam(uintptr_t player)
{
    return Mem->Read<int>(player + m_iTeamNum);
}

int CFunctions::GetCrosshairID(uintptr_t player)
{
    return Mem->Read<int>(player + m_iCrosshairId);
}

void CFunctions::TriggerBot(int delay, int key)
{
    if (this->GetCrosshairID(this->GetLocalPlayer()) > 0 &&
        this->GetCrosshairID(this->GetLocalPlayer()) < 32 &&
        this->GetTeam(this->GetLocalPlayer()) != this->GetTeam(this->GetPlayer(this->GetCrosshairID(this->GetLocalPlayer()) - 1))) 
    {
        // Use mouse_event is not good pratice but i'm lazy
        // TODO: implement shot
        mouse_event(MOUSEEVENTF_LEFTDOWN, NULL, NULL, 0, 0);
        mouse_event(MOUSEEVENTF_LEFTUP, NULL, NULL, 0, 0);
        Sleep(100);
    }

    // NOTE: This "this" is not necessary but is good pratice
}

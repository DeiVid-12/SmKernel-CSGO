# SmKernel-CSGO

### SmKernel-CSGO is a educational project that's show how a driver can be used to hack games.

<p>SmKernel use a kernel driver that's make a shared memory communication. Driver have simple cheat functions like get module base and Read/Write in memory.</p>

<p>This project is maded in my free time and i make this very fast so this probably has some bugs.</p>
<p>The project is simpel, i just add a simple triggerbot, just for poc.</p>

# Can VAC detect this cheat ?
<p>Problaly no, because vac don't have a kernel driver that's can detect this feautures.</p>
<p>To make sure it's undetectable you can add obCallBacks to the usermode app, but I don't think it's necessary for such a weak anticheat.</p>

# Can kernel anticheats detect this cheat ?
<p>Yes, because I didn't build this driver with security as a priority.</p>
<p>So a kernel anticheat can easily detect this</p>


# Compiling
- Download visual studio 2019
- Install Windows Driver Kit (WDK)
- Download the project
- Open solution and compile for x64

# How to start
- Put computer on test mode
```bcdedit /set testsigning on```
- Restart your computer
- Create a service for driver ```sc create smk type=kernel binpath="path to driver"```
- Start the service ```sc start smk```

### Note: It's not a safe mode to load a cheat driver, look for methods to manual map your driver with a vulnerable driver

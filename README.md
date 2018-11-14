# ViewInjectedThread
Project for CSEC464. Get Injected threads of a process on a system that have been injected with the metasploit framework.

## Usage
./injectview PID

Injectview will then display if there are any threads that have been injected with along with a count displayed at the end.

## Explination

Injected view uses the Windows native API to query information about threads that cannot be obtained through the normal API. The API call that is being used is NtQueryInformationThread. Because this is a native function, it is not exported, and we must manually export it. To do this, we can use a function called GetPRocAddress. This will do the dirty work of searching through the Dll and grabbing the address of the function. We can then use this with a custom function to call the function directly. 

From using this function, we can grab important information about each thread in a process such as start address, name, and so on. The vital thing here is the start address, as when using the "migrate" tool in the Metasploit framework, we see that start address is out of range of each of the loaded modules with the process. It is important to note that the loaded modules for each process are essentially the externally linked libraries, or the Dlls that are used with the process. For whatever reason, Metasploit's migrate function does not properly set the start address of the thread and therefore, it can be easily detected.

This tool was written in C++, as it allows for the direct access to the all-powerful WINAPI and the native API. This, in combination with my own familiarity with the language is the biggest reason for it being the chosen language of this program. Hopefully this tool will help people see that there are different ways to detect thread injection and that a little bit of creativity can go a long way. It should also be helpful to forensics investigators such that they can better get an idea of how to use the powerful Windows API to detect these sorts of attacks on an operating system.

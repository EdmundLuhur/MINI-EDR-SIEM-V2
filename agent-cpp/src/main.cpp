// Mini EDR Process Snapshot Collector
//
// Goal:
// This program will scan Linux /proc and collect basic process telemetry.
//
// Steps:
// 1. Open the /proc directory.
// 2. Find folders that are only numbers.
// 3. Treat each numbered folder as a process ID.
// 4. Read /proc/[pid]/status to get process name, PID, PPID and UID.
// 5. Read /proc/[pid]/cmdline to get the command line.
// 6. Replace hidden null characters in cmdline with spaces.
// 7. Try to read /proc/[pid]/exe to get the executable path.
// 8. If a field cannot be read, use fallback values like unavailable or permission_denied.
// 9. Print each process clearly.
// 10. Exit.


// Data structure idea:
// ProcessInfo should store one process event.
// It needs PID, PPID, process name, UID, command line and executable path.

#include <iostream>
#include <string>
#include <fstream>


struct ProcessInfo{
// the struct/type name 
    int pid;
    int ppid;
    int uid;
    std::string name;
    std::string command_line;
    std::string exe_path;
};

int main(){
    ProcessInfo processInfo;
// the variable/object name
    processInfo.pid = -1;
    processInfo.ppid = -1;
    processInfo.uid = -1;
    processInfo.name = "unavailable";
    processInfo.command_line = "unavailable";
    processInfo.exe_path = "unavailable";


    std::ifstream statusFile("/proc/1/status");

    if (!statusFile.is_open()) {
        std::cout <<"Error: Could not open /proc/1/status" << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(statusFile, line)) {
        if(line.find("Name:") == 0) {
            processInfo.name = line.substr(6);
        }
        // look for Name, Pid, PPid and Uid.
    
    }


    std::cout <<"PID: " << processInfo.pid << std::endl;
    std::cout << "PPID: " << processInfo.ppid << std::endl;
    std::cout << "UID: " << processInfo.uid << std::endl;
    std::cout << "Name: " << processInfo.name << std::endl;
    std::cout << "Command Line: " << processInfo.command_line << std::endl;
    std::cout << "Executable Path: " << processInfo.exe_path << std::endl;

    return 0;
}



// Next goal:
// Read /proc/1/status instead of using fake data.
// Open the status file.
// Read each line.
// Look for Name, Pid, PPid and Uid.
// Store those values in ProcessInfo.
// Print the result.
// Mini EDR Process Snapshot Collector
//
// Purpose:
// This C++ agent scans the Linux /proc filesystem and collects basic
// process telemetry. This is similar to what an EDR agent would do at a
// very basic level.
//
// What it collects for each process:
// - PID
// - Parent PID
// - UID
// - Process name
// - Command line
// - Executable path
//
// Important Linux concept:
// /proc is a virtual filesystem. It exposes live information about
// running processes. Each running process usually has a folder like:
//
// /proc/1
// /proc/123
// /proc/456
//
// The number is the PID.

#include <iostream>     // For std::cout and std::cerr
#include <string>       // For std::string
#include <fstream>      // For reading files using std::ifstream
#include <sstream>      // For converting text into numbers
#include <unistd.h>     // For readlink()
#include <sys/types.h>  // For ssize_t
#include <dirent.h>     // For opendir(), readdir(), closedir()
#include <cctype>       // For std::isdigit()
#include <vector>       // For std::vector
#include <algorithm>    // For std::sort()

// This struct stores one process snapshot.
// Think of it like one telemetry event for one Linux process.
struct ProcessInfo {
    int pid;
    int ppid;
    int uid;
    std::string name;
    std::string command_line;
    std::string exe_path;
};

// This helper function checks if a folder name is only numbers.
//
// Why?
// /proc contains many folders/files, such as:
// /proc/cpuinfo
// /proc/meminfo
// /proc/sys
// /proc/1
// /proc/123
//
// Only numeric folders represent process IDs.
bool isNumericName(const std::string& name) {
    // Empty names are not valid PIDs.
    if (name.empty()) {
        return false;
    }

    // Check every character.
    // If even one character is not a digit, return false.
    for (char ch : name) {
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }

    return true;
}

// This function collects process information for one PID.
//
// Example:
// collectProcessInfo(1) reads:
// /proc/1/status
// /proc/1/cmdline
// /proc/1/exe
ProcessInfo collectProcessInfo(int targetPid) {
    ProcessInfo processInfo;

    // Fallback/default values.
    //
    // These are used when the process field cannot be read.
    // This is realistic for EDR tooling because some process files may be
    // protected or the process may disappear while we are scanning.
    processInfo.pid = -1;
    processInfo.ppid = -1;
    processInfo.uid = -1;
    processInfo.name = "unavailable";
    processInfo.command_line = "unavailable";
    processInfo.exe_path = "unavailable";

    // Build dynamic /proc paths using the target PID.
    //
    // Example if targetPid = 123:
    // statusPath  = /proc/123/status
    // cmdlinePath = /proc/123/cmdline
    // exePath     = /proc/123/exe
    std::string statusPath = "/proc/" + std::to_string(targetPid) + "/status";
    std::string cmdlinePath = "/proc/" + std::to_string(targetPid) + "/cmdline";
    std::string exePath = "/proc/" + std::to_string(targetPid) + "/exe";

    // ------------------------------------------------------------
    // 1. Read /proc/[pid]/status
    // ------------------------------------------------------------
    //
    // This file contains process metadata like:
    // Name:   systemd
    // Pid:    1
    // PPid:   0
    // Uid:    0    0    0    0
    std::ifstream statusFile(statusPath);

    if (statusFile.is_open()) {
        std::string line;

        // Read the status file line by line.
        while (std::getline(statusFile, line)) {

            // Parse PID.
            //
            // Example line:
            // Pid:    1
            //
            // line.substr(4) removes "Pid:"
            // stringstream converts the remaining text into an integer.
            if (line.rfind("Pid:", 0) == 0) {
                std::stringstream ss(line.substr(4));
                ss >> processInfo.pid;
            }

            // Parse parent PID.
            //
            // Example line:
            // PPid:   0
            //
            // PPid is useful in cybersecurity because suspicious behaviour
            // often appears in parent-child process relationships.
            if (line.rfind("PPid:", 0) == 0) {
                std::stringstream ss(line.substr(5));
                ss >> processInfo.ppid;
            }

            // Parse UID.
            //
            // Example line:
            // Uid:    0    0    0    0
            //
            // We only take the first UID for now.
            // UID 0 usually means root.
            if (line.rfind("Uid:", 0) == 0) {
                std::stringstream ss(line.substr(4));
                ss >> processInfo.uid;
            }

            // Parse process name.
            //
            // Example line:
            // Name:   systemd
            if (line.rfind("Name:", 0) == 0) {
                processInfo.name = line.substr(6);
            }
        }
    }

    // ------------------------------------------------------------
    // 2. Read /proc/[pid]/cmdline
    // ------------------------------------------------------------
    //
    // This file contains the command used to start the process.
    //
    // Important:
    // Linux stores command-line arguments separated by null bytes '\0',
    // not normal spaces.
    //
    // Example raw style:
    // python3\0server.py\0--port\05000
    //
    // We convert '\0' into spaces so the output is readable:
    // python3 server.py --port 5000
    std::ifstream cmdlineFile(cmdlinePath);

    if (cmdlineFile.is_open()) {
        std::string cmdlineContent;
        char ch;

        // Read one character at a time so we can detect null bytes.
        while (cmdlineFile.get(ch)) {
            if (ch == '\0') {
                ch = ' ';
            }

            cmdlineContent += ch;
        }

        // Only replace the fallback value if we actually read content.
        if (!cmdlineContent.empty()) {
            processInfo.command_line = cmdlineContent;
        }
    }

    // ------------------------------------------------------------
    // 3. Read /proc/[pid]/exe
    // ------------------------------------------------------------
    //
    // /proc/[pid]/exe is not a normal text file.
    // It is a symbolic link pointing to the real executable.
    //
    // Example:
    // /proc/1/exe -> /usr/lib/systemd/systemd
    //
    // We use readlink() because std::ifstream is not the right tool
    // for reading symbolic link targets.
    char exeBuffer[4096];

    // readlink() writes the symlink target into exeBuffer.
    //
    // Important:
    // readlink() does NOT automatically add '\0' at the end,
    // so we leave one byte free by using sizeof(exeBuffer) - 1.
    ssize_t exeLength = readlink(exePath.c_str(), exeBuffer, sizeof(exeBuffer) - 1);

    // If readlink succeeds, it returns the number of bytes written.
    // If it fails, it returns -1.
    //
    // Failure can happen because:
    // - permission denied
    // - process disappeared
    // - process is protected
    if (exeLength != -1) {
        // Manually add the null terminator so exeBuffer becomes a valid string.
        exeBuffer[exeLength] = '\0';

        // Store executable path in the process snapshot.
        processInfo.exe_path = exeBuffer;
    }

    return processInfo;
}

std::string escapeJsonString(const std::string& input) {
    std::string output;

    for (char c : input) {
        if (c == '"') {
            output += "\\\"";
        } else if (c == '\\') {
            output += "\\\\";
        } else if (c == '\n') {
            output += "\\n";
        } else if (c == '\t') {
            output += "\\t";
        } else {
            output += c;
        }
    }

    return output;
}

std::string processInfoToJson(const ProcessInfo& processInfo) {
    std::ostringstream json;

    json << "{";
    json << "\"pid\":" << processInfo.pid << ",";
    json << "\"ppid\":" << processInfo.ppid << ",";
    json << "\"uid\":" << processInfo.uid << ",";
    json << "\"name\":\"" << escapeJsonString(processInfo.name) << "\",";
    json << "\"command_line\":\"" << escapeJsonString(processInfo.command_line) << "\",";
    json << "\"exe_path\":\"" << escapeJsonString(processInfo.exe_path) << "\"";
    json << "}";

    return json.str();
}
// This function prints one process snapshot clearly.
//
// Keeping printing separate from collection makes the code cleaner.
// Later, we can replace this with JSON export without changing the collector logic.
void printProcessInfo(const ProcessInfo& processInfo) {
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "PID: " << processInfo.pid << std::endl;
    std::cout << "PPID: " << processInfo.ppid << std::endl;
    std::cout << "UID: " << processInfo.uid << std::endl;
    std::cout << "Name: " << processInfo.name << std::endl;
    std::cout << "Command Line: " << processInfo.command_line << std::endl;
    std::cout << "Executable Path: " << processInfo.exe_path << std::endl;
}

int main() {
    // Open the /proc directory.
    //
    // This is where Linux exposes process information.
    DIR* procDir = opendir("/proc");

    // If /proc cannot be opened, stop the program.
    if (procDir == nullptr) {
        std::cerr << "Error: Could not open /proc" << std::endl;
        return 1;
    }

    // Store discovered process IDs here.
    std::vector<int> pids;

    // readdir() returns directory entries from /proc one by one.
    dirent* entry;

    while ((entry = readdir(procDir)) != nullptr) {
        std::string entryName = entry->d_name;

        // Only numeric folder names are process IDs.
        //
        // Example:
        // "1" is a PID
        // "123" is a PID
        // "cpuinfo" is not a PID
        if (isNumericName(entryName)) {
            try {
                // Convert folder name from string to integer PID.
                int pid = std::stoi(entryName);
                pids.push_back(pid);
            } catch (...) {
                // If conversion fails for any reason, ignore it.
                //
                // This keeps the scanner stable instead of crashing.
            }
        }
    }

    // Always close the directory after finishing.
    closedir(procDir);

    // Sort PIDs so the output is easier to read.
    std::sort(pids.begin(), pids.end());

    //std::cout << "Mini EDR Process Snapshot Collector" << std::endl;
    //std::cout << "Processes found: " << pids.size() << std::endl;

    // Collect and print information for each PID.
    for (int pid : pids) {
        ProcessInfo processInfo = collectProcessInfo(pid);

        // Skip processes that disappeared before we could read them.
        //
        // This can happen because processes start and stop constantly.
        if (processInfo.pid == -1) {
            continue;
        }

        std::cout << processInfoToJson(processInfo) << std::endl;
    }

    return 0;
}
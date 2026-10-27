#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>

// Structure to hold a valid memory segment
struct MemoryRange {
    uintptr_t start;
    uintptr_t end;
    std::string permissions;
};

// Function to parse /proc/self/maps and find readable memory regions
std::vector<MemoryRange> getReadableRegions() {
    std::vector<MemoryRange> regions;
    std::ifstream mapsFile("/proc/self/maps");
    
    if (!mapsFile.is_open()) {
        std::cerr << "Failed to open memory map file." << std::endl;
        return regions;
    }

    std::string line;
    while (std::getline(mapsFile, line)) {
        std::stringstream ss(line);
        std::string addressRange, permissions;
        
        // Example line format: 00400000-00452000 r-xp 00000000 ...
        if (ss >> addressRange >> permissions) {
            // We only want regions we can actually read ('r')
            if (permissions.length() > 0 && permissions[0] == 'r') {
                size_t dashPos = addressRange.find('-');
                if (dashPos != std::string::npos) {
                    uintptr_t start = std::stoull(addressRange.substr(0, dashPos), nullptr, 16);
                    uintptr_t end = std::stoull(addressRange.substr(dashPos + 1), nullptr, 16);
                    
                    regions.push_back({start, end, permissions});
                }
            }
        }
    }
    return regions;
}

int main() {
    std::cout << "[+] Gathering valid, readable memory maps..." << std::endl;
    std::vector<MemoryRange> regions = getReadableRegions();

    std::cout << "[+] Found " << regions.size() << " safe readable regions." << std::endl;

    // Loop through each safe region discovered
    for (const auto& region : regions) {
        std::cout << "\nScanning Region: 0x" << std::hex << region.start 
                  << " - 0x" << region.end << " [" << region.permissions << "]\n";

        // Loop from the lowest safe address to the highest safe address in this block
        for (uintptr_t addr = region.start; addr < region.end; ++addr) {
            // Safely cast the integer memory address back to a pointer
            uint8_t* ptr = reinterpret_cast<uint8_t*>(addr);
            
            // To prevent flooding the terminal, this example prints out the first 16 bytes 
            // of each region. Remove this specific condition to dump everything.
            if (addr < region.start + 16) {
                std::cout << "  Address: 0x" << std::hex << std::setw(12) << std::setfill('0') << addr 
                          << " | Value: 0x" << std::setw(2) << static_cast<int>(*ptr) << std::endl;
            } else {
                std::cout << "  ... [truncating remainder of region to protect terminal overflow] ..." << std::endl;
                break;
            }
        }
    }

    std::cout << "\n[+] Finished scanning safe regions. Wrapping back around complete." << std::endl;
    return 0;
}

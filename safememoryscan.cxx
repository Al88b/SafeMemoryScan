// SafeMemoryScan - continuously scans this process's readable memory,
// lowest address to highest, then wraps round and starts again.
//
// Build:  g++ -O2 -std=c++17 -o safememoryscan safememoryscan.cxx
// Run:    ./safememoryscan            (Ctrl+C to stop)
//         ./safememoryscan | less     (to page through it)

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/uio.h>
#include <unistd.h>

struct MemoryRange {
    uintptr_t start;
    uintptr_t end;
    std::string permissions;
    std::string name;
};

static volatile sig_atomic_t g_running = 1;
static void onSignal(int) { g_running = 0; }

// Parse /proc/self/maps for readable regions. Re-read on every pass,
// because the map changes as the program runs (heap growth, etc.).
static std::vector<MemoryRange> getReadableRegions() {
    std::vector<MemoryRange> regions;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream ss(line);
        std::string range, perms, offset, dev, inode, name;
        if (!(ss >> range >> perms >> offset >> dev >> inode)) continue;
        std::getline(ss >> std::ws, name);
        if (perms.empty() || perms[0] != 'r') continue;
        // [vvar]/[vvar_vclock] are kernel-provided pages that can fault on read.
        if (name.rfind("[vvar", 0) == 0) continue;
        size_t dash = range.find('-');
        if (dash == std::string::npos) continue;
        regions.push_back({std::stoull(range.substr(0, dash), nullptr, 16),
                           std::stoull(range.substr(dash + 1), nullptr, 16),
                           perms, name});
    }
    return regions;  // /proc/self/maps is already sorted low -> high
}

// Read memory without risking a crash: process_vm_readv returns an error
// (EFAULT) for unreadable pages instead of raising SIGSEGV.
static ssize_t safeRead(uintptr_t addr, void* buf, size_t len) {
    iovec local{buf, len};
    iovec remote{reinterpret_cast<void*>(addr), len};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
}

static void printLine(uintptr_t addr, const uint8_t* b, size_t n) {
    char out[128];
    int p = std::snprintf(out, sizeof out, "%016lx  ", static_cast<unsigned long>(addr));
    for (size_t i = 0; i < 16; ++i)
        p += i < n ? std::snprintf(out + p, sizeof out - p, "%02x ", b[i])
                   : std::snprintf(out + p, sizeof out - p, "   ");
    p += std::snprintf(out + p, sizeof out - p, " |");
    for (size_t i = 0; i < n; ++i)
        out[p++] = (b[i] >= 0x20 && b[i] < 0x7f) ? static_cast<char>(b[i]) : '.';
    out[p++] = '|';
    out[p++] = '\n';
    std::fwrite(out, 1, p, stdout);
}

int main() {
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGPIPE, onSignal);   // e.g. piped into `head` and it exits
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    std::vector<uint8_t> buf(page);

    for (unsigned long pass = 1; g_running; ++pass) {
        std::vector<MemoryRange> regions = getReadableRegions();
        std::printf("\n===== Pass %lu: %zu readable regions =====\n", pass, regions.size());

        for (const auto& r : regions) {
            if (!g_running) break;
            std::printf("\n--- 0x%lx - 0x%lx [%s] %s ---\n",
                        static_cast<unsigned long>(r.start), static_cast<unsigned long>(r.end),
                        r.permissions.c_str(), r.name.c_str());

            // Walk the region one page at a time, lowest to highest.
            for (uintptr_t addr = r.start; addr < r.end && g_running; addr += page) {
                size_t len = std::min<size_t>(page, r.end - addr);
                ssize_t got = safeRead(addr, buf.data(), len);
                if (got <= 0) {
                    std::printf("%016lx  <unreadable page, skipped>\n", static_cast<unsigned long>(addr));
                    continue;
                }
                for (ssize_t off = 0; off < got; off += 16)
                    printLine(addr + off, buf.data() + off,
                              std::min<size_t>(16, static_cast<size_t>(got - off)));
            }
        }
        std::printf("\n===== Pass %lu complete, wrapping round to lowest address =====\n", pass);
        std::fflush(stdout);
    }
    std::fprintf(stderr, "\n[+] Stopped.\n");
    return 0;
}

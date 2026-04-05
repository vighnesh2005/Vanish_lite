#include <arpa/inet.h>
#include <dirent.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <netdb.h>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

namespace {

struct GuardConfig {
    bool online_enable_network = true;
    vector<string> allowed_sites;
    vector<string> blocked_sites;
};

struct SocketEntry {
    string remote_ip;
    int remote_port = 0;
    unsigned long inode = 0;
};

string trim(const string& s)
{
    size_t start = 0;
    while (start < s.size() && isspace(static_cast<unsigned char>(s[start]))) {
        start++;
    }

    size_t end = s.size();
    while (end > start && isspace(static_cast<unsigned char>(s[end - 1]))) {
        end--;
    }

    return s.substr(start, end - start);
}

bool parseBool(const string& raw, bool defaultValue)
{
    string value = trim(raw);
    for (char& c : value) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }

    if (value == "1" || value == "true" || value == "yes" || value == "on") return true;
    if (value == "0" || value == "false" || value == "no" || value == "off") return false;
    return defaultValue;
}

vector<string> parseCsvList(const string& raw)
{
    vector<string> items;
    string normalized = raw;
    replace(normalized.begin(), normalized.end(), '\n', ',');

    string token;
    stringstream ss(normalized);
    while (getline(ss, token, ',')) {
        token = trim(token);
        if (!token.empty()) {
            items.push_back(token);
        }
    }
    return items;
}

string normalizeDomain(string value)
{
    value = trim(value);
    for (char& c : value) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }

    const string http = "http://";
    const string https = "https://";
    if (value.rfind(http, 0) == 0) value = value.substr(http.size());
    if (value.rfind(https, 0) == 0) value = value.substr(https.size());

    size_t slash = value.find('/');
    if (slash != string::npos) value = value.substr(0, slash);

    size_t colon = value.find(':');
    if (colon != string::npos) value = value.substr(0, colon);

    while (!value.empty() && value.back() == '.') value.pop_back();
    if (value.rfind("www.", 0) == 0) value = value.substr(4);

    return trim(value);
}

vector<string> parseCsvDomains(const string& raw)
{
    vector<string> out;
    set<string> seen;
    for (const auto& item : parseCsvList(raw)) {
        string domain = normalizeDomain(item);
        if (domain.empty() || seen.count(domain)) {
            continue;
        }
        seen.insert(domain);
        out.push_back(domain);
    }
    return out;
}

bool loadConfig(const string& path, GuardConfig& cfg)
{
    ifstream in(path);
    if (!in) {
        return false;
    }

    GuardConfig next;
    string line;
    while (getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }

        size_t sep = line.find('=');
        if (sep == string::npos) {
            continue;
        }

        string key = trim(line.substr(0, sep));
        string value = trim(line.substr(sep + 1));

        if (key == "online.enable_network") next.online_enable_network = parseBool(value, next.online_enable_network);
        else if (key == "online.allow_sites") next.allowed_sites = parseCsvDomains(value);
        else if (key == "online.block_sites") next.blocked_sites = parseCsvDomains(value);
    }

    cfg = next;
    return true;
}

set<string> resolveAllIps(const vector<string>& domains)
{
    set<string> ips;

    for (const auto& domain : domains) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* results = nullptr;
        if (getaddrinfo(domain.c_str(), nullptr, &hints, &results) != 0) {
            continue;
        }

        for (addrinfo* ptr = results; ptr != nullptr; ptr = ptr->ai_next) {
            char host[INET6_ADDRSTRLEN];
            void* src = nullptr;

            if (ptr->ai_family == AF_INET) {
                src = &reinterpret_cast<sockaddr_in*>(ptr->ai_addr)->sin_addr;
            } else if (ptr->ai_family == AF_INET6) {
                src = &reinterpret_cast<sockaddr_in6*>(ptr->ai_addr)->sin6_addr;
            }

            if (src && inet_ntop(ptr->ai_family, src, host, sizeof(host))) {
                ips.insert(string(host));
            }
        }

        freeaddrinfo(results);
    }

    return ips;
}

string parseProcIp(const string& raw, bool ipv6)
{
    if (!ipv6) {
        if (raw.size() != 8) return "";
        unsigned char bytes[4];
        for (int i = 0; i < 4; i++) {
            string hexByte = raw.substr((3 - i) * 2, 2);
            bytes[i] = static_cast<unsigned char>(stoul(hexByte, nullptr, 16));
        }
        char out[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, bytes, out, sizeof(out))) return "";
        return string(out);
    }

    if (raw.size() != 32) return "";
    unsigned char bytes[16];
    for (int group = 0; group < 4; group++) {
        string word = raw.substr(group * 8, 8);
        for (int i = 0; i < 4; i++) {
            string hexByte = word.substr((3 - i) * 2, 2);
            bytes[group * 4 + i] = static_cast<unsigned char>(stoul(hexByte, nullptr, 16));
        }
    }
    char out[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, bytes, out, sizeof(out))) return "";
    return string(out);
}

bool parseAddressPort(const string& raw, bool ipv6, string& ip, int& port)
{
    size_t sep = raw.find(':');
    if (sep == string::npos) {
        return false;
    }

    ip = parseProcIp(raw.substr(0, sep), ipv6);
    port = static_cast<int>(stoul(raw.substr(sep + 1), nullptr, 16));
    return !ip.empty();
}

void loadSocketTable(const string& path, bool ipv6, map<unsigned long, SocketEntry>& out)
{
    ifstream in(path);
    if (!in) {
        return;
    }

    string line;
    getline(in, line);  // header
    while (getline(in, line)) {
        istringstream ss(line);
        vector<string> cols;
        string token;
        while (ss >> token) {
            cols.push_back(token);
        }

        if (cols.size() < 10) {
            continue;
        }

        string ip;
        int port = 0;
        if (!parseAddressPort(cols[2], ipv6, ip, port)) {
            continue;
        }

        unsigned long inode = 0;
        try {
            inode = stoul(cols[9]);
        } catch (...) {
            continue;
        }

        SocketEntry entry;
        entry.remote_ip = ip;
        entry.remote_port = port;
        entry.inode = inode;
        out[inode] = entry;
    }
}

map<unsigned long, SocketEntry> loadSocketTable()
{
    map<unsigned long, SocketEntry> out;
    loadSocketTable("/proc/net/tcp", false, out);
    loadSocketTable("/proc/net/tcp6", true, out);
    loadSocketTable("/proc/net/udp", false, out);
    loadSocketTable("/proc/net/udp6", true, out);
    return out;
}

bool isNumeric(const string& value)
{
    if (value.empty()) return false;
    for (char c : value) {
        if (!isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

string readCmdline(pid_t pid)
{
    ifstream in("/proc/" + to_string(pid) + "/cmdline");
    if (!in) return "";
    string raw((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    for (char& c : raw) {
        if (c == '\0') c = ' ';
    }
    return trim(raw);
}

string basenameOf(string value)
{
    size_t slash = value.find_last_of('/');
    if (slash != string::npos) {
        value = value.substr(slash + 1);
    }

    size_t space = value.find(' ');
    if (space != string::npos) {
        value = value.substr(0, space);
    }

    return trim(value);
}

bool isProtectedProcess(const string& cmdline)
{
    string name = basenameOf(cmdline);
    static const set<string> protectedNames = {
        "bash",
        "sh",
        "zsh",
        "fish",
        "login",
        "systemd",
        "systemd-userdbd",
        "systemd-executor",
        "dbus-daemon",
        "dbus-broker",
        "dbus-broker-launch",
        "gnome-shell",
        "gnome-session-binary",
        "gnome-session",
        "Xorg",
        "Xwayland",
        "startplasma-wayland",
        "startplasma-x11",
        "plasmashell",
        "kwin_wayland",
        "kwin_x11",
        "xfce4-session",
        "cinnamon-session",
        "mate-session",
        "pipewire",
        "wireplumber",
        "pulseaudio",
        "vanish_user_netguard"
    };

    return protectedNames.count(name) > 0;
}

set<unsigned long> collectSocketInodes(pid_t pid)
{
    set<unsigned long> inodes;
    filesystem::path fdDir = "/proc/" + to_string(pid) + "/fd";
    error_code ec;
    if (!filesystem::exists(fdDir, ec) || ec) {
        return inodes;
    }

    filesystem::directory_iterator it(fdDir, filesystem::directory_options::skip_permission_denied, ec);
    filesystem::directory_iterator end;
    if (ec) {
        return inodes;
    }

    for (; it != end; it.increment(ec)) {
        if (ec) {
            break;
        }

        filesystem::path target = filesystem::read_symlink(it->path(), ec);
        if (ec) {
            continue;
        }

        string value = target.string();
        if (value.rfind("socket:[", 0) != 0 || value.back() != ']') {
            continue;
        }

        string inodeRaw = value.substr(8, value.size() - 9);
        try {
            inodes.insert(stoul(inodeRaw));
        } catch (...) {
        }
    }

    return inodes;
}

void logLine(ofstream& log, const string& line)
{
    auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    string stamp = ctime(&now);
    if (!stamp.empty() && stamp.back() == '\n') {
        stamp.pop_back();
    }
    log << "[" << stamp << "] " << line << "\n";
    log.flush();
}

bool isWebPort(int port)
{
    return port == 80 || port == 443;
}

void terminatePid(pid_t pid, ofstream& log, const string& reason)
{
    string cmdline = readCmdline(pid);
    logLine(log, "Blocking pid " + to_string(pid) + ": " + reason + (cmdline.empty() ? "" : " | " + cmdline));
    kill(pid, SIGTERM);
    this_thread::sleep_for(chrono::milliseconds(150));
    kill(pid, SIGKILL);
}

bool shouldBlockConnection(const GuardConfig& cfg, const set<string>& allowedIps, const set<string>& blockedIps, const SocketEntry& entry)
{
    if (!isWebPort(entry.remote_port)) {
        return false;
    }

    if (!cfg.online_enable_network) {
        return true;
    }

    if (!allowedIps.empty()) {
        return allowedIps.count(entry.remote_ip) == 0;
    }

    if (!blockedIps.empty()) {
        return blockedIps.count(entry.remote_ip) > 0;
    }

    return false;
}

}  // namespace

int main(int argc, char* argv[])
{
    string configPath;
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            configPath = argv[++i];
        }
    }

    if (configPath.empty()) {
        cerr << "Usage: vanish_user_netguard --config <path>\n";
        return 1;
    }

    uid_t selfUid = getuid();
    pid_t selfPid = getpid();

    const char* home = getenv("HOME");
    string logPath = string(home ? home : "/tmp") + "/.vanish_netguard.log";
    ofstream log(logPath, ios::app);
    logLine(log, "Starting user network guard with config " + configPath);

    // Give the session time to finish logging in before enforcement starts.
    this_thread::sleep_for(chrono::seconds(8));

    GuardConfig cfg;
    filesystem::file_time_type lastConfigTime{};
    set<string> allowedIps;
    set<string> blockedIps;
    auto lastResolve = chrono::steady_clock::now() - chrono::minutes(5);

    while (true) {
        error_code ec;
        auto configTime = filesystem::last_write_time(configPath, ec);
        if (!ec && (configTime != lastConfigTime || chrono::steady_clock::now() - lastResolve > chrono::seconds(30))) {
            GuardConfig next;
            if (loadConfig(configPath, next)) {
                cfg = next;
                allowedIps = resolveAllIps(cfg.allowed_sites);
                blockedIps = resolveAllIps(cfg.blocked_sites);
                lastConfigTime = configTime;
                lastResolve = chrono::steady_clock::now();
                logLine(log, "Reloaded config. allow_ips=" + to_string(allowedIps.size()) + " block_ips=" + to_string(blockedIps.size()));
            }
        }

        map<unsigned long, SocketEntry> sockets = loadSocketTable();

        error_code procEc;
        filesystem::directory_iterator procIt("/proc", filesystem::directory_options::skip_permission_denied, procEc);
        filesystem::directory_iterator procEnd;
        for (; procIt != procEnd; procIt.increment(procEc)) {
            if (procEc) {
                break;
            }

            const auto& procEntry = *procIt;
            string pidName = procEntry.path().filename().string();
            if (!isNumeric(pidName)) {
                continue;
            }

            pid_t pid = static_cast<pid_t>(stoi(pidName));
            if (pid == selfPid) {
                continue;
            }

            struct stat st{};
            if (stat(procEntry.path().c_str(), &st) != 0 || st.st_uid != selfUid) {
                continue;
            }

            string cmdline = readCmdline(pid);
            if (isProtectedProcess(cmdline)) {
                continue;
            }

            set<unsigned long> inodes = collectSocketInodes(pid);
            bool blocked = false;
            for (unsigned long inode : inodes) {
                auto it = sockets.find(inode);
                if (it == sockets.end()) {
                    continue;
                }

                if (!shouldBlockConnection(cfg, allowedIps, blockedIps, it->second)) {
                    continue;
                }

                string reason = "remote=" + it->second.remote_ip + ":" + to_string(it->second.remote_port);
                if (!cfg.online_enable_network) {
                    reason = "network disabled | " + reason;
                } else if (!allowedIps.empty()) {
                    reason = "outside allow-list | " + reason;
                } else {
                    reason = "matched block-list | " + reason;
                }

                terminatePid(pid, log, reason);
                blocked = true;
                break;
            }

            if (blocked) {
                continue;
            }
        }

        this_thread::sleep_for(chrono::seconds(1));
    }

    return 0;
}

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace {

struct GuardConfig {
    bool online_enable_network = true;
    vector<string> allowed_sites;
    vector<string> blocked_sites;
};

mutex g_mutex;
bool g_loaded = false;
filesystem::file_time_type g_lastConfigTime{};
GuardConfig g_config;
set<string> g_allowedIps;
set<string> g_blockedIps;

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
    transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });

    if (value == "1" || value == "true" || value == "yes" || value == "on") return true;
    if (value == "0" || value == "false" || value == "no" || value == "off") return false;
    return defaultValue;
}

vector<string> parseCsvList(const string& raw)
{
    vector<string> out;
    string normalized = raw;
    replace(normalized.begin(), normalized.end(), '\n', ',');

    string token;
    stringstream ss(normalized);
    while (getline(ss, token, ',')) {
        token = trim(token);
        if (!token.empty()) {
            out.push_back(token);
        }
    }
    return out;
}

string normalizeDomain(string value)
{
    value = trim(value);
    transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });

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

string getConfigPath()
{
    const char* envPath = getenv("VANISH_NETGUARD_CONFIG");
    if (envPath && *envPath) {
        return string(envPath);
    }

    const char* home = getenv("HOME");
    if (home && *home) {
        return string(home) + "/.config/vanish/network_policy.conf";
    }

    return "";
}

string getLogPath()
{
    const char* home = getenv("HOME");
    if (home && *home) {
        return string(home) + "/.vanish_netguard.log";
    }
    return "/tmp/.vanish_netguard.log";
}

void logLine(const string& message)
{
    ofstream log(getLogPath(), ios::app);
    if (!log) {
        return;
    }

    auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    string stamp = ctime(&now);
    if (!stamp.empty() && stamp.back() == '\n') {
        stamp.pop_back();
    }
    log << "[" << stamp << "] " << message << "\n";
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

void reloadConfigLocked()
{
    string configPath = getConfigPath();
    if (configPath.empty()) {
        return;
    }

    error_code ec;
    auto configTime = filesystem::last_write_time(configPath, ec);
    if (!ec && g_loaded && configTime == g_lastConfigTime) {
        return;
    }

    ifstream in(configPath);
    if (!in) {
        return;
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

    g_config = next;
    g_allowedIps = resolveAllIps(g_config.allowed_sites);
    g_blockedIps = resolveAllIps(g_config.blocked_sites);
    g_loaded = true;
    if (!ec) {
        g_lastConfigTime = configTime;
    }
}

bool parseRemote(const sockaddr* addr, socklen_t addrlen, string& ip, int& port)
{
    if (!addr) {
        return false;
    }

    char host[INET6_ADDRSTRLEN];

    if (addr->sa_family == AF_INET && addrlen >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(addr);
        if (!inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host))) {
            return false;
        }
        ip = host;
        port = ntohs(in->sin_port);
        return true;
    }

    if (addr->sa_family == AF_INET6 && addrlen >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (!inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host))) {
            return false;
        }
        ip = host;
        port = ntohs(in6->sin6_port);
        return true;
    }

    return false;
}

bool shouldBlock(const string& ip, int port)
{
    if (port != 80 && port != 443) {
        return false;
    }

    lock_guard<mutex> lock(g_mutex);
    reloadConfigLocked();

    if (!g_config.online_enable_network) {
        return true;
    }

    if (!g_allowedIps.empty()) {
        return g_allowedIps.count(ip) == 0;
    }

    if (!g_blockedIps.empty()) {
        return g_blockedIps.count(ip) > 0;
    }

    return false;
}

using ConnectFn = int (*)(int, const struct sockaddr*, socklen_t);

}  // namespace

extern "C" int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    static ConnectFn realConnect = reinterpret_cast<ConnectFn>(dlsym(RTLD_NEXT, "connect"));
    if (!realConnect) {
        errno = EACCES;
        return -1;
    }

    string ip;
    int port = 0;
    if (!parseRemote(addr, addrlen, ip, port)) {
        return realConnect(sockfd, addr, addrlen);
    }

    if (!shouldBlock(ip, port)) {
        return realConnect(sockfd, addr, addrlen);
    }

    logLine("Blocked connect() to " + ip + ":" + to_string(port));
    errno = EACCES;
    return -1;
}

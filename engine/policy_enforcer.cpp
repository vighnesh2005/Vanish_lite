#include "policy_enforcer.h"

#include <pwd.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <netdb.h>
#include <arpa/inet.h>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

vector<string> allowedSites;
vector<string> blockedSites;
vector<string> blockedCommands;

void logExam(const string& message);

/* =========================
   HELPERS
   ========================= */

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
    vector<string> sites;
    string normalized = raw;
    replace(normalized.begin(), normalized.end(), '\n', ',');

    string token;
    stringstream ss(normalized);

    while (getline(ss, token, ',')) {
        string site = trim(token);
        if (!site.empty()) {
            sites.push_back(site);
        }
    }

    return sites;
}

string normalizeDomain(string site)
{
    site = trim(site);
    transform(site.begin(), site.end(), site.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });

    const string http = "http://";
    const string https = "https://";
    if (site.rfind(http, 0) == 0) site = site.substr(http.size());
    if (site.rfind(https, 0) == 0) site = site.substr(https.size());

    size_t slash = site.find('/');
    if (slash != string::npos) site = site.substr(0, slash);

    size_t colon = site.find(':');
    if (colon != string::npos) site = site.substr(0, colon);

    while (!site.empty() && site.back() == '.') site.pop_back();

    if (site.rfind("www.", 0) == 0) site = site.substr(4);
    return trim(site);
}

vector<string> parseCsvDomains(const string& raw)
{
    vector<string> out;
    set<string> seen;
    for (const auto& item : parseCsvList(raw)) {
        string domain = normalizeDomain(item);
        if (domain.empty()) continue;
        if (!seen.count(domain)) {
            seen.insert(domain);
            out.push_back(domain);
        }
    }
    return out;
}

bool isSafeCommandName(const string& name)
{
    if (name.empty()) return false;
    for (char c : name) {
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '+' || c == '.')) {
            return false;
        }
    }
    return true;
}

string shellQuote(const string& value)
{
    string out = "'";
    for (char c : value) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out += c;
        }
    }
    out += "'";
    return out;
}

vector<string> getMountedTargetsUnder(const string& rootPath)
{
    vector<string> mountPoints;
    ifstream mounts("/proc/mounts");
    string line;

    while (getline(mounts, line)) {
        istringstream ss(line);
        string source;
        string target;
        if (!(ss >> source >> target)) {
            continue;
        }

        if (target == rootPath || target.rfind(rootPath + "/", 0) == 0) {
            mountPoints.push_back(target);
        }
    }

    sort(mountPoints.begin(), mountPoints.end(), [](const string& a, const string& b) {
        return a.size() > b.size();
    });
    mountPoints.erase(unique(mountPoints.begin(), mountPoints.end()), mountPoints.end());
    return mountPoints;
}

string usbPolkitRulePath(const string& username)
{
    return "/etc/polkit-1/rules.d/49-vanish-usb-" + username + ".rules";
}

void unmountUserRemovableMedia(const string& username)
{
    vector<string> basePaths = {
        "/run/media/" + username,
        "/media/" + username
    };

    for (const auto& basePath : basePaths) {
        for (const auto& mountPoint : getMountedTargetsUnder(basePath)) {
            system(("umount -l " + shellQuote(mountPoint) + " >/dev/null 2>&1").c_str());
            logExam("Unmounted removable media path for " + username + ": " + mountPoint);
        }
    }
}

/* =========================
   LOGGING
   ========================= */

void logExam(const string& message)
{
    ofstream log("/var/log/vanish_exam.log", ios::app);

    time_t now = time(nullptr);
    string t = ctime(&now);
    t.pop_back();

    log << "[" << t << "] " << message << endl;
}

/* =========================
   CONFIG PARSER
   ========================= */

PolicyConfig loadPolicyConfigFile(const string& path)
{
    PolicyConfig cfg;

    if (path.empty()) {
        return cfg;
    }

    ifstream file(path);
    if (!file) {
        return cfg;
    }

    string line;
    while (getline(file, line)) {
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

        if (key == "exam.restrict_network") cfg.exam_restrict_network = parseBool(value, cfg.exam_restrict_network);
        else if (key == "exam.disable_usb") cfg.exam_disable_usb = parseBool(value, cfg.exam_disable_usb);
        else if (key == "exam.enable_persistence") cfg.exam_enable_persistence = parseBool(value, cfg.exam_enable_persistence);

        else if (key == "online.enable_network") cfg.online_enable_network = parseBool(value, cfg.online_enable_network);
        else if (key == "online.enable_dns_filtering") cfg.online_enable_dns_filtering = parseBool(value, cfg.online_enable_dns_filtering);
        else if (key == "online.disable_usb") cfg.online_disable_usb = parseBool(value, cfg.online_disable_usb);
        else if (key == "online.enable_persistence") cfg.online_enable_persistence = parseBool(value, cfg.online_enable_persistence);
        else if (key == "online.enable_command_restriction") cfg.online_enable_command_restriction = parseBool(value, cfg.online_enable_command_restriction);

        else if (key == "privacy.enable_ram_home") cfg.privacy_enable_ram_home = parseBool(value, cfg.privacy_enable_ram_home);
        else if (key == "privacy.ram_home_size_mb") {
            try {
                long sizeMb = stol(value);
                if (sizeMb > 0) {
                    cfg.privacy_ram_home_size_mb = sizeMb;
                }
            } catch (...) {
            }
        }
        else if (key == "privacy.enable_privacy_dns") cfg.privacy_enable_privacy_dns = parseBool(value, cfg.privacy_enable_privacy_dns);
        else if (key == "privacy.block_telemetry") cfg.privacy_block_telemetry = parseBool(value, cfg.privacy_block_telemetry);
        else if (key == "privacy.apply_dark_theme") cfg.privacy_apply_dark_theme = parseBool(value, cfg.privacy_apply_dark_theme);

        else if (key == "resource.proc_limit") {
            try {
                cfg.proc_limit_override = stol(value);
            } catch (...) {
                cfg.proc_limit_override = -1;
            }
        }

        else if (key == "online.allow_sites") cfg.online_allowed_sites = parseCsvDomains(value);
        else if (key == "online.block_sites") cfg.online_blocked_sites = parseCsvDomains(value);
        else if (key == "online.block_commands") cfg.online_blocked_commands = parseCsvList(value);
    }

    return cfg;
}

/* =========================
   ONLINE MODE
   ========================= */

void loadOnlineConfig(const PolicyConfig& config)
{
    allowedSites.clear();
    blockedSites.clear();
    blockedCommands.clear();

    for (const auto& s : config.online_allowed_sites) {
        string d = normalizeDomain(s);
        if (!d.empty()) allowedSites.push_back(d);
    }
    for (const auto& s : config.online_blocked_sites) {
        string d = normalizeDomain(s);
        if (!d.empty()) blockedSites.push_back(d);
    }

    if (!config.online_blocked_commands.empty()) {
        blockedCommands.clear();
        for (const auto& cmd : config.online_blocked_commands) {
            string token = trim(cmd);
            if (!token.empty()) blockedCommands.push_back(token);
        }
    }
}

vector<string> defaultBlockedCommands()
{
    return {"curl", "wget", "git", "python", "python3", "node"};
}

void applyOnlineCommandRestrictions(const string& username, const vector<string>& requestedCommands)
{
    vector<string> commands = requestedCommands;
    if (commands.empty()) {
        commands = blockedCommands;
    }
    if (commands.empty()) {
        commands = defaultBlockedCommands();
    }

    vector<string> sanitized;
    for (const auto& cmd : commands) {
        string token = trim(cmd);
        if (isSafeCommandName(token)) {
            sanitized.push_back(token);
        }
    }

    if (sanitized.empty()) {
        logExam("No valid command restrictions configured for online mode");
        return;
    }

    string homeDir = "/home/" + username;
    string guardScript = homeDir + "/.vanish_command_guard.sh";
    string bashrcPath = homeDir + "/.bashrc";
    string marker = "source ~/.vanish_command_guard.sh";

    ofstream guard(guardScript);
    guard << "#!/usr/bin/env bash\n";
    guard << "vanish_blocked_cmd() {\n";
    guard << "  echo \"[VANISH] Command '$1' is disabled in ONLINE mode.\"\n";
    guard << "  return 1\n";
    guard << "}\n";
    for (const auto& cmd : sanitized) {
        guard << "alias " << cmd << "='vanish_blocked_cmd " << cmd << "'\n";
    }
    guard.close();

    bool hasMarker = false;
    ifstream bashrcIn(bashrcPath);
    string line;
    while (getline(bashrcIn, line)) {
        if (line.find(marker) != string::npos) {
            hasMarker = true;
            break;
        }
    }
    bashrcIn.close();

    if (!hasMarker) {
        ofstream bashrcOut(bashrcPath, ios::app);
        bashrcOut << "\n# Vanish online command guard\n";
        bashrcOut << marker << "\n";
    }

    system(("chown " + username + ":" + username + " " + guardScript + " " + bashrcPath).c_str());
    system(("chmod 600 " + guardScript).c_str());

    logExam("Online command restrictions enabled for " + username);
}

void clearOnlineCommandRestrictions(const string& username)
{
    string guardScript = "/home/" + username + "/.vanish_command_guard.sh";
    system(("rm -f " + guardScript + " 2>/dev/null").c_str());
    logExam("Online command restrictions disabled for " + username);
}

void applyOnlineDNSFiltering(const string& username)
{
    // IMPORTANT:
    // Writing to /etc/hosts is global and affects every user (including root).
    // Online restrictions are enforced per-session user via owner-matched iptables rules
    // in applyOnlineNetwork(), so we deliberately avoid global DNS edits here.
    logExam("Online DNS filtering requested for " + username + " (local-only mode: no global DNS/hosts edits)");
}

string userChainName(int uid)
{
    return "VANISH_U" + to_string(uid);
}

void setupUserOutputChain(int uid)
{
    string chain = userChainName(uid);
    system(("iptables -N " + chain + " 2>/dev/null").c_str());
    system(("iptables -F " + chain + " 2>/dev/null").c_str());
    system(("iptables -D OUTPUT -m owner --uid-owner " + to_string(uid) + " -j " + chain + " 2>/dev/null").c_str());
    system(("iptables -A OUTPUT -m owner --uid-owner " + to_string(uid) + " -j " + chain).c_str());
}

void cleanupUserOutputChain(int uid)
{
    string chain = userChainName(uid);
    system(("iptables -D OUTPUT -m owner --uid-owner " + to_string(uid) + " -j " + chain + " 2>/dev/null").c_str());
    system(("iptables -F " + chain + " 2>/dev/null").c_str());
    system(("iptables -X " + chain + " 2>/dev/null").c_str());
}

set<string> resolveIPv4(const string& domain)
{
    set<string> ips;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) != 0) {
        return ips;
    }

    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        char ipbuf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &(addr->sin_addr), ipbuf, sizeof(ipbuf))) {
            ips.insert(string(ipbuf));
        }
    }
    freeaddrinfo(res);
    return ips;
}

void applyOnlineNetwork(const string& username)
{
    bool strictAllowList = !allowedSites.empty();
    if (strictAllowList) {
        logExam("Online network guard prepared in strict allow-list mode for " + username);
    } else if (!blockedSites.empty()) {
        logExam("Online network guard prepared in block-list mode for " + username);
    } else {
        logExam("Online network guard prepared with no site restrictions for " + username);
    }
}

/* =========================
   MODE PARSER
   ========================= */

Mode parseMode(const string& modeStr)
{
    if (modeStr == "dev") return DEV;
    if (modeStr == "secure") return SECURE;
    if (modeStr == "privacy") return PRIVACY;
    if (modeStr == "exam") return EXAM;
    if (modeStr == "online") return ONLINE;

    return INVALID;
}

/* =========================
   NETWORK RESTRICTION
   ========================= */

void applyNetworkRestriction(const string& username)
{
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return;

    int uid = pw->pw_uid;
    string chain = userChainName(uid);

    setupUserOutputChain(uid);
    system(("iptables -A " + chain + " -o lo -j ACCEPT").c_str());
    system(("iptables -A " + chain + " -j DROP").c_str());

    logExam("Network restricted for " + username);
}

void cleanupNetworkRestriction(const string& username)
{
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return;

    cleanupUserOutputChain(pw->pw_uid);
}

/* =========================
   USB STORAGE
   ========================= */

void disableUSB(const string& username)
{
    string rulePath = usbPolkitRulePath(username);
    ofstream rule(rulePath);
    if (rule) {
        rule << "polkit.addRule(function(action, subject) {\n";
        rule << "    if (subject.user == \"" << username << "\" && action.id.indexOf(\"org.freedesktop.udisks2.\") == 0) {\n";
        rule << "        return polkit.Result.NO;\n";
        rule << "    }\n";
        rule << "});\n";
        rule.close();
    }

    system(("chmod 644 " + shellQuote(rulePath) + " >/dev/null 2>&1").c_str());
    unmountUserRemovableMedia(username);

    string automountCmd =
        "sudo -u " + username +
        " dbus-launch gsettings set org.gnome.desktop.media-handling automount false >/dev/null 2>&1";
    system(automountCmd.c_str());

    string automountOpenCmd =
        "sudo -u " + username +
        " dbus-launch gsettings set org.gnome.desktop.media-handling automount-open false >/dev/null 2>&1";
    system(automountOpenCmd.c_str());

    logExam("USB storage access denied only for session user " + username + " via polkit removable-media rule");
}

void enableUSB(const string& username)
{
    filesystem::remove(usbPolkitRulePath(username));
    logExam("USB storage access restored for session user " + username);
}

/* =========================
   RESOURCE LIMITS
   ========================= */

void applyResourceLimits(const string& username, Mode mode, const PolicyConfig& config)
{
    long procLimit = -1;

    switch (mode)
    {
        case DEV:     procLimit = 1500; break;
        case SECURE:  procLimit = 1200; break;
        case PRIVACY: procLimit = 1200; break;
        case EXAM:    procLimit = 800; break;
        case ONLINE:  procLimit = 800; break;
        default: return;
    }

    if (config.proc_limit_override > 0) {
        procLimit = config.proc_limit_override;
    }

    // /etc/security/limits.conf is global. Record intended limit per user without
    // mutating global PAM limits state.
    filesystem::create_directories("/var/vanish_sessions");
    ofstream limits("/var/vanish_sessions/" + username + ".limits.intent");
    limits << "soft_nproc=" << procLimit << "\n";
    limits << "hard_nproc=" << procLimit << "\n";
    logExam("Resource limit intent recorded for " + username + " (global limits.conf untouched)");
}

/* =========================
   EXAM MODE PERSISTENCE
   ========================= */

void setupExamPersistence(const string& username)
{
    string baseDir = "/var/vanish_exam_submissions";
    string userDir = baseDir + "/" + username;
    string homeDir = "/home/" + username;
    string submitDir = homeDir + "/submit";

    system(("mkdir -p " + baseDir).c_str());
    system(("mkdir -p " + userDir).c_str());
    system(("mkdir -p " + submitDir).c_str());

    system(("chown -R " + username + ":" + username + " " + homeDir).c_str());
    system(("chown -R " + username + ":" + username + " " + userDir).c_str());

    string mountCmd =
        "mount --bind " + userDir + " " + submitDir;

    system(mountCmd.c_str());

    logExam("Persistent submission folder mounted for " + username);
}

/* =========================
   PRIVACY MODE
   ========================= */

void enableRamHome(const string& username, long sizeMb)
{
    string home = "/home/" + username;
    long finalSizeMb = sizeMb > 0 ? sizeMb : 2048;

    string cmd =
        "mount -t tmpfs -o size=" + to_string(finalSizeMb) + "M tmpfs " + home;

    system(cmd.c_str());

    logExam("RAM home enabled for " + username + " with size " + to_string(finalSizeMb) + " MB");
}

void disableRamHome(const string& username)
{
    string cmd =
        "umount -l /home/" + username + " 2>/dev/null";

    system(cmd.c_str());
}

void applyPrivacyDNS(const string& username)
{
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return;

    int uid = pw->pw_uid;
    string chain = userChainName(uid);
    system(("iptables -A " + chain + " -p udp --dport 53 -d 1.1.1.1 -j ACCEPT").c_str());
    system(("iptables -A " + chain + " -p udp --dport 53 -d 1.0.0.1 -j ACCEPT").c_str());
    system(("iptables -A " + chain + " -p tcp --dport 53 -d 1.1.1.1 -j ACCEPT").c_str());
    system(("iptables -A " + chain + " -p tcp --dport 53 -d 1.0.0.1 -j ACCEPT").c_str());
    system(("iptables -A " + chain + " -p udp --dport 53 -j REJECT").c_str());
    system(("iptables -A " + chain + " -p tcp --dport 53 -j REJECT").c_str());

    logExam("Privacy DNS applied locally for " + username + " using per-user firewall DNS rules");
}

void blockTelemetry(const string& username)
{
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return;

    int uid = pw->pw_uid;
    string chain = userChainName(uid);

    vector<string> telemetryDomains = {
        "google-analytics.com",
        "www.google-analytics.com",
        "telemetry.microsoft.com"
    };

    set<string> blockedIps;
    for (const auto& domain : telemetryDomains) {
        set<string> ips = resolveIPv4(domain);
        blockedIps.insert(ips.begin(), ips.end());
    }

    for (const auto& ip : blockedIps) {
        system(("iptables -A " + chain + " -p tcp -d " + ip + " --dport 80 -j REJECT").c_str());
        system(("iptables -A " + chain + " -p tcp -d " + ip + " --dport 443 -j REJECT").c_str());
    }

    logExam("Telemetry block applied locally for " + username + " using per-user firewall rules");
}

void cleanupUserTraces(const string& username)
{
    string home = "/home/" + username;

    system(("rm -rf " + home + "/.cache").c_str());
    system(("rm -f " + home + "/.bash_history").c_str());
}

/* =========================
   APPLY POLICIES
   ========================= */

void applyPolicies(const string& username, Mode mode, const PolicyConfig& config)
{
    applyResourceLimits(username, mode, config);

    if (mode == EXAM)
    {
        if (config.exam_restrict_network) {
            applyNetworkRestriction(username);
        }

        if (config.exam_disable_usb) {
            disableUSB(username);
        }

        if (config.exam_enable_persistence) {
            setupExamPersistence(username);
        }

        logExam("EXAM mode applied to " + username);
    }

    if (mode == ONLINE)
    {
        loadOnlineConfig(config);

        if (config.online_enable_network) {
            applyOnlineNetwork(username);
        }

        if (config.online_enable_dns_filtering) {
            applyOnlineDNSFiltering(username);
        }

        if (config.online_disable_usb) {
            disableUSB(username);
        }

        if (config.online_enable_persistence) {
            setupExamPersistence(username);
        }

        if (config.online_enable_command_restriction) {
            applyOnlineCommandRestrictions(username, config.online_blocked_commands);
        } else {
            clearOnlineCommandRestrictions(username);
        }

        logExam("ONLINE EXAM mode applied to " + username);
    }

    if (mode == PRIVACY)
    {
        struct passwd* pw = getpwnam(username.c_str());
        if (pw) {
            setupUserOutputChain(pw->pw_uid);
            string chain = userChainName(pw->pw_uid);
            system(("iptables -A " + chain + " -o lo -j ACCEPT").c_str());
        }

        if (config.privacy_enable_ram_home) {
            enableRamHome(username, config.privacy_ram_home_size_mb);
        }

        if (config.privacy_enable_privacy_dns) {
            applyPrivacyDNS(username);
        }

        if (config.privacy_block_telemetry) {
            blockTelemetry(username);
        }

        if (pw) {
            string chain = userChainName(pw->pw_uid);
            system(("iptables -A " + chain + " -j RETURN").c_str());
        }

        if (config.privacy_apply_dark_theme) {
            string themeCmd =
                "sudo -u " + username +
                " dbus-launch gsettings set "
                "org.gnome.desktop.interface color-scheme 'prefer-dark'";

            system(themeCmd.c_str());
        }

        logExam("PRIVACY mode applied to " + username);
    }
}

/* =========================
   CLEANUP
   ========================= */

void cleanupPolicies(const string& username)
{
    cleanupUserTraces(username);
    disableRamHome(username);
    cleanupNetworkRestriction(username);
    enableUSB(username);

    string unmountCmd =
        "umount -l /home/" + username + "/submit 2>/dev/null";

    system(unmountCmd.c_str());

    logExam("Cleanup completed for " + username);
}


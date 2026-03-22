#include "session.h"

#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <pwd.h>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>

#include "session_manager.h"
#include "utils.h"

using namespace std;
const string SESSION_DIR_PATH = "/var/vanish_sessions/";
const string MANAGED_USERS_FILE = "/var/vanish_sessions/.managed_users";

bool isValidLinuxUsername(const string& username)
{
    // Typical Linux-safe username pattern.
    static const regex pattern("^[a-z_][a-z0-9_-]{0,30}$");
    return regex_match(username, pattern);
}

bool isValidPassword(const string& password)
{
    if (password.empty()) return false;
    if (password.find(':') != string::npos) return false;
    if (password.find('\n') != string::npos) return false;
    return true;
}

string modeToString(Mode mode)
{
    switch (mode) {
        case DEV: return "dev";
        case SECURE: return "secure";
        case PRIVACY: return "privacy";
        case EXAM: return "exam";
        case ONLINE: return "online";
        default: return "unknown";
    }
}

bool setUserPassword(const string& username, const string& password)
{
    string tmpPath = "/tmp/vanish_chpasswd_" + to_string(getpid()) + "_" + username;

    ofstream tmp(tmpPath);
    if (!tmp) {
        return false;
    }

    tmp << username << ":" << password << "\n";
    tmp.close();

    string cmd = "chpasswd < " + tmpPath;
    int result = system(cmd.c_str());

    remove(tmpPath.c_str());
    return result == 0;
}

void startLogoutWatcher(const string& username, bool persistUntilShutdown)
{
    if (persistUntilShutdown) {
        return;
    }

    // Watcher deletes the session only after the user has been seen logged in once
    // and then has no remaining processes (logout complete).
    string cmd =
        "nohup bash -c '"
        "u=\"" + username + "\"; "
        "seen=0; "
        "for i in $(seq 1 17280); do "  // up to 24h (5s interval)
        "if ! id \"$u\" >/dev/null 2>&1; then exit 0; fi; "
        "if pgrep -u \"$u\" >/dev/null 2>&1; then "
        "seen=1; "
        "else "
        "if [ \"$seen\" -eq 1 ]; then "
        "uid=$(id -u \"$u\" 2>/dev/null || true); "
        "if [ -n \"$uid\" ]; then "
        "chain=\"VANISH_U${uid}\"; "
        "iptables -D OUTPUT -m owner --uid-owner \"$uid\" -j \"$chain\" >/dev/null 2>&1; "
        "iptables -F \"$chain\" >/dev/null 2>&1; "
        "iptables -X \"$chain\" >/dev/null 2>&1; "
        "fi; "
        "pkill -9 -u \"$u\" >/dev/null 2>&1; "
        "loginctl terminate-user \"$u\" >/dev/null 2>&1; "
        "umount -l /home/\"$u\"/submit >/dev/null 2>&1; "
        "umount -l /home/\"$u\" >/dev/null 2>&1; "
        "userdel -f -r \"$u\" >/dev/null 2>&1; "
        "rm -f /var/vanish_sessions/\"$u\" "
        "/var/vanish_sessions/\"$u\".policy.conf "
        "/var/vanish_sessions/\"$u\".online.conf "
        "/var/vanish_sessions/\"$u\".monitor.conf "
        "/var/vanish_sessions/\"$u\".limits.intent "
        "/var/vanish_sessions/\"$u\".report.json >/dev/null 2>&1; "
        "if [ -f /var/vanish_sessions/.managed_users ]; then "
        "tmp=$(mktemp); "
        "grep -vx \"$u\" /var/vanish_sessions/.managed_users > \"$tmp\" 2>/dev/null; "
        "cat \"$tmp\" > /var/vanish_sessions/.managed_users; "
        "rm -f \"$tmp\"; "
        "fi; "
        "exit 0; "
        "fi; "
        "fi; "
        "sleep 5; "
        "done' >/dev/null 2>&1 &";

    system(cmd.c_str());
}

string joinCsv(const vector<string>& items)
{
    ostringstream out;
    for (size_t i = 0; i < items.size(); i++) {
        if (i > 0) out << ",";
        out << items[i];
    }
    return out.str();
}

string currentExecutableDir()
{
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        return filesystem::current_path().string();
    }

    buffer[len] = '\0';
    return filesystem::path(buffer).parent_path().string();
}

void ensureLineBlock(const string& path, const string& marker, const string& block)
{
    string current;
    ifstream in(path);
    if (in) {
        current.assign((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    }

    if (current.find(marker) != string::npos) {
        return;
    }

    ofstream out(path, ios::app);
    if (!current.empty() && current.back() != '\n') {
        out << "\n";
    }
    out << "\n" << block;
}

void removeLineBlock(const string& path, const string& marker)
{
    ifstream in(path);
    if (!in) {
        return;
    }

    string content((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    size_t start = content.find(marker);
    if (start == string::npos) {
        return;
    }

    size_t end = content.find("\nfi\n", start);
    if (end == string::npos) {
        return;
    }
    end += 4;

    content.erase(start, end - start);

    ofstream out(path, ios::trunc);
    out << content;
}

void installOnlineUserGuard(const string& username, const PolicyConfig& config)
{
    string homeDir = "/home/" + username;
    string configDir = homeDir + "/.config/vanish";
    string envDir = homeDir + "/.config/environment.d";
    string localBinDir = homeDir + "/.local/bin";
    string localLibDir = homeDir + "/.local/lib";
    string policyPath = configDir + "/network_policy.conf";
    string guardPath = localBinDir + "/vanish_user_netguard";
    string preloadLibPath = localLibDir + "/libvanish_netguard.so";
    string envPath = envDir + "/90-vanish-netguard.conf";
    string bashrcPath = homeDir + "/.bashrc";
    string profilePath = homeDir + "/.profile";

    filesystem::create_directories(configDir);
    filesystem::create_directories(envDir);
    filesystem::create_directories(localBinDir);
    filesystem::create_directories(localLibDir);

    string sourceGuard = currentExecutableDir() + "/vanish_user_netguard";
    if (filesystem::exists(sourceGuard)) {
        filesystem::copy_file(sourceGuard, guardPath, filesystem::copy_options::overwrite_existing);
    }
    string sourcePreload = currentExecutableDir() + "/libvanish_netguard.so";
    if (filesystem::exists(sourcePreload)) {
        filesystem::copy_file(sourcePreload, preloadLibPath, filesystem::copy_options::overwrite_existing);
    }

    ofstream policy(policyPath);
    policy << "# Vanish user-local network guard config\n";
    policy << "online.enable_network=" << (config.online_enable_network ? "true" : "false") << "\n";
    policy << "online.allow_sites=" << joinCsv(config.online_allowed_sites) << "\n";
    policy << "online.block_sites=" << joinCsv(config.online_blocked_sites) << "\n";
    policy.close();

    ofstream envFile(envPath);
    envFile << "LD_PRELOAD=" << preloadLibPath << "\n";
    envFile << "VANISH_NETGUARD_CONFIG=" << policyPath << "\n";
    envFile.close();

    const string marker = "# Vanish network guard startup";
    removeLineBlock(profilePath, marker);
    removeLineBlock(bashrcPath, marker);

    const string bashrcBlock =
        "# Vanish network guard startup\n"
        "export VANISH_NETGUARD_CONFIG=\"$HOME/.config/vanish/network_policy.conf\"\n"
        "case \":${LD_PRELOAD:-}:\" in\n"
        "  *\":$HOME/.local/lib/libvanish_netguard.so:\"*) ;;\n"
        "  *) export LD_PRELOAD=\"$HOME/.local/lib/libvanish_netguard.so${LD_PRELOAD:+:$LD_PRELOAD}\" ;;\n"
        "esac\n";
    ensureLineBlock(bashrcPath, marker, bashrcBlock);

    system(("chown -R " + username + ":" + username + " " + configDir + " " + envDir + " " + localBinDir + " " + localLibDir + " " + bashrcPath).c_str());
    system(("chmod 700 " + localBinDir).c_str());
    system(("chmod 755 " + localLibDir).c_str());
    system(("chmod 700 " + configDir + " " + envDir).c_str());
    system(("chmod 755 " + guardPath + " " + preloadLibPath).c_str());
    system(("chmod 644 " + policyPath + " " + envPath + " " + bashrcPath).c_str());
}

set<string> readManagedUsers()
{
    set<string> users;
    ifstream in(MANAGED_USERS_FILE);
    string user;
    static const regex userPattern("^[a-z_][a-z0-9_-]{0,30}$");
    while (getline(in, user)) {
        if (regex_match(user, userPattern)) {
            users.insert(user);
        }
    }
    return users;
}

void writeManagedUsers(const set<string>& users)
{
    filesystem::create_directories(SESSION_DIR_PATH);
    ofstream out(MANAGED_USERS_FILE);
    for (const auto& user : users) {
        out << user << "\n";
    }
}

void registerManagedUser(const string& username)
{
    set<string> users = readManagedUsers();
    users.insert(username);
    writeManagedUsers(users);
}

void unregisterManagedUser(const string& username)
{
    set<string> users = readManagedUsers();
    users.erase(username);
    writeManagedUsers(users);
}

void writeSessionConfigSnapshots(const string& username, Mode mode, const PolicyConfig& config)
{
    filesystem::create_directories(SESSION_DIR_PATH);

    string base = SESSION_DIR_PATH + username;
    string policyPath = base + ".policy.conf";
    string onlinePath = base + ".online.conf";
    string monitorPath = base + ".monitor.conf";

    ofstream policy(policyPath);
    policy << "# Vanish session policy snapshot\n";
    policy << "mode=" << modeToString(mode) << "\n";
    policy << "exam.restrict_network=" << (config.exam_restrict_network ? "true" : "false") << "\n";
    policy << "exam.disable_usb=" << (config.exam_disable_usb ? "true" : "false") << "\n";
    policy << "exam.enable_persistence=" << (config.exam_enable_persistence ? "true" : "false") << "\n";
    policy << "online.enable_network=" << (config.online_enable_network ? "true" : "false") << "\n";
    policy << "online.enable_dns_filtering=" << (config.online_enable_dns_filtering ? "true" : "false") << "\n";
    policy << "online.disable_usb=" << (config.online_disable_usb ? "true" : "false") << "\n";
    policy << "online.enable_persistence=" << (config.online_enable_persistence ? "true" : "false") << "\n";
    policy << "online.enable_command_restriction=" << (config.online_enable_command_restriction ? "true" : "false") << "\n";
    policy << "online.allow_sites=" << joinCsv(config.online_allowed_sites) << "\n";
    policy << "online.block_sites=" << joinCsv(config.online_blocked_sites) << "\n";
    policy << "online.block_commands=" << joinCsv(config.online_blocked_commands) << "\n";
    policy << "privacy.enable_ram_home=" << (config.privacy_enable_ram_home ? "true" : "false") << "\n";
    policy << "privacy.ram_home_size_mb=" << config.privacy_ram_home_size_mb << "\n";
    policy << "privacy.enable_privacy_dns=" << (config.privacy_enable_privacy_dns ? "true" : "false") << "\n";
    policy << "privacy.block_telemetry=" << (config.privacy_block_telemetry ? "true" : "false") << "\n";
    policy << "privacy.apply_dark_theme=" << (config.privacy_apply_dark_theme ? "true" : "false") << "\n";
    policy << "resource.proc_limit=" << config.proc_limit_override << "\n";
    policy.close();

    ofstream online(onlinePath);
    online << "# Vanish session online snapshot\n";
    for (const auto& site : config.online_allowed_sites) {
        if (!site.empty()) online << "allow:" << site << "\n";
    }
    for (const auto& site : config.online_blocked_sites) {
        if (!site.empty()) online << "block:" << site << "\n";
    }
    for (const auto& cmd : config.online_blocked_commands) {
        if (!cmd.empty()) online << "cmd:" << cmd << "\n";
    }
    online.close();

    ofstream monitor(monitorPath);
    monitor << "# Vanish session monitor snapshot\n";
    monitor << "mode=" << modeToString(mode) << "\n";
    for (const auto& cmd : config.online_blocked_commands) {
        if (!cmd.empty()) monitor << "cmd:" << cmd << "\n";
    }
    for (const auto& site : config.online_blocked_sites) {
        if (!site.empty()) monitor << "site:" << site << "\n";
    }
    monitor.close();
}

void writeSessionComplianceReport(const string& username, Mode mode, const PolicyConfig& config, bool persistUntilShutdown)
{
    string reportPath = SESSION_DIR_PATH + username + ".report.json";
    ofstream report(reportPath);
    if (!report) return;

    report << "{\n";
    report << "  \"username\": \"" << username << "\",\n";
    report << "  \"mode\": \"" << modeToString(mode) << "\",\n";
    report << "  \"persist_until_shutdown\": " << (persistUntilShutdown ? "true" : "false") << ",\n";
    report << "  \"defaults_applied\": {\n";
    report << "    \"exam_restrict_network\": " << (config.exam_restrict_network ? "true" : "false") << ",\n";
    report << "    \"exam_disable_usb\": " << (config.exam_disable_usb ? "true" : "false") << ",\n";
    report << "    \"exam_enable_persistence\": " << (config.exam_enable_persistence ? "true" : "false") << ",\n";
    report << "    \"online_enable_network\": " << (config.online_enable_network ? "true" : "false") << ",\n";
    report << "    \"online_enable_dns_filtering\": " << (config.online_enable_dns_filtering ? "true" : "false") << ",\n";
    report << "    \"online_disable_usb\": " << (config.online_disable_usb ? "true" : "false") << ",\n";
    report << "    \"online_enable_persistence\": " << (config.online_enable_persistence ? "true" : "false") << ",\n";
    report << "    \"online_enable_command_restriction\": " << (config.online_enable_command_restriction ? "true" : "false") << ",\n";
    report << "    \"privacy_enable_ram_home\": " << (config.privacy_enable_ram_home ? "true" : "false") << ",\n";
    report << "    \"privacy_ram_home_size_mb\": " << config.privacy_ram_home_size_mb << ",\n";
    report << "    \"privacy_enable_privacy_dns\": " << (config.privacy_enable_privacy_dns ? "true" : "false") << ",\n";
    report << "    \"privacy_block_telemetry\": " << (config.privacy_block_telemetry ? "true" : "false") << ",\n";
    report << "    \"privacy_apply_dark_theme\": " << (config.privacy_apply_dark_theme ? "true" : "false") << ",\n";
    report << "    \"proc_limit_override\": " << config.proc_limit_override << "\n";
    report << "  }\n";
    report << "}\n";
}

void deleteSessionSnapshots(const string& username)
{
    string base = SESSION_DIR_PATH + username;
    filesystem::remove(base + ".policy.conf");
    filesystem::remove(base + ".online.conf");
    filesystem::remove(base + ".monitor.conf");
    filesystem::remove(base + ".limits.intent");
    filesystem::remove(base + ".report.json");
}

void forceDeleteUserSession(const string& username)
{
    cleanupPolicies(username);

    // Best-effort termination of all user processes and sessions.
    system(("pkill -9 -u " + username + " 2>/dev/null").c_str());
    system(("loginctl terminate-user " + username + " 2>/dev/null").c_str());
    system(("umount -l /home/" + username + "/submit 2>/dev/null").c_str());
    system(("userdel -f -r " + username + " 2>/dev/null").c_str());

    deleteSessionRecord(username);
    deleteSessionSnapshots(username);
    unregisterManagedUser(username);
}

void createSession(Mode mode, const string& requestedUsername, const string& requestedPassword, const PolicyConfig& config, bool persistUntilShutdown)
{
    string username = requestedUsername.empty() ? generateUsername() : requestedUsername;

    if (!isValidLinuxUsername(username)) {
        cerr << "Invalid username. Use lowercase letters, numbers, _ or -, and start with a letter/_ .\n";
        exit(1);
    }

    if (userExists(username)) {
        cerr << "Username already exists.\n";
        exit(1);
    }

    string password = requestedPassword.empty() ? "temporary_user" : requestedPassword;
    if (!isValidPassword(password)) {
        cerr << "Invalid password. Password cannot be empty, contain ':' or new lines.\n";
        exit(1);
    }

    cout << "[INFO] Creating user: " << username << endl;

    string addUserCmd = "useradd -m -s /bin/bash " + username;
    if (system(addUserCmd.c_str()) != 0) {
        cerr << "Failed to create user.\n";
        exit(1);
    }

    if (!setUserPassword(username, password)) {
        cerr << "Failed to set password.\n";
        system(("userdel -f -r " + username + " 2>/dev/null").c_str());
        exit(1);
    }

    applyPolicies(username, mode, config);
    if (mode == ONLINE) {
        installOnlineUserGuard(username, config);
    }
    createSessionRecord(username, modeToString(mode), persistUntilShutdown);
    registerManagedUser(username);
    writeSessionConfigSnapshots(username, mode, config);
    writeSessionComplianceReport(username, mode, config, persistUntilShutdown);
    startLogoutWatcher(username, persistUntilShutdown);

    cout << "\n=====================================\n";
    cout << "Vanish user created.\n";
    cout << "Username: " << username << endl;
    cout << "Password: " << password << "\n";
    cout << "Mode applied successfully.\n";
    cout << "=====================================\n";
}

void stopSession()
{
    set<string> usernames;

    for (const auto& s : getActiveSessions()) {
        if (!s.username.empty()) {
            usernames.insert(s.username);
        }
    }

    // Include any record files directly to avoid missing users when parse fails.
    if (filesystem::exists(SESSION_DIR_PATH)) {
        static const regex userPattern("^[a-z_][a-z0-9_-]{0,30}$");
        for (const auto& entry : filesystem::directory_iterator(SESSION_DIR_PATH)) {
            if (!entry.is_regular_file()) continue;
            string name = entry.path().filename().string();
            if (regex_match(name, userPattern)) {
                usernames.insert(name);
            }
        }
    }

    // Include managed-user registry to handle missing/partial session record cases.
    set<string> managed = readManagedUsers();
    usernames.insert(managed.begin(), managed.end());

    for (const auto& username : usernames) {
        forceDeleteUserSession(username);
    }

    cout << "[INFO] Cleanup completed.\n";
}

#include "policy_enforcer.h"
#include <pwd.h>
#include <cstdlib>
#include <fstream>
#include <ctime>
#include <string>

#include <vector>

vector<string> allowedSites;
vector<string> blockedSites;

using namespace std;

/* =========================
   LOGGING
   ========================= */

void logExam(const string& message)
{
    ofstream log("/var/log/vanish_exam.log", ios::app);

    time_t now = time(nullptr);
    string t = ctime(&now);
    t.pop_back();   // remove newline

    log << "[" << t << "] " << message << endl;
}

void loadOnlineConfig() {

    ifstream file("/etc/vanish/online.conf");
    string line;

    while(getline(file, line)) {

        if(line.find("allow:") == 0)
            allowedSites.push_back(line.substr(6));

        if(line.find("block:") == 0)
            blockedSites.push_back(line.substr(6));
    }
}

void applyOnlineDNSFiltering() {

    ofstream hosts("/etc/hosts", ios::app);

    for(auto &site : blockedSites) {
        hosts << "0.0.0.0 " << site << "\n";
    }

    hosts.close();
}

void applyOnlineNetwork(const string& username) {

    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return;

    int uid = pw->pw_uid;

    // allow loopback
    string allowLoop =
        "iptables -A OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -o lo -j ACCEPT";

    system(allowLoop.c_str());

    // allow DNS
    system(("iptables -A OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -p udp --dport 53 -j ACCEPT").c_str());

    // allow HTTP/HTTPS
    system(("iptables -A OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -p tcp --dport 80 -j ACCEPT").c_str());

    system(("iptables -A OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -p tcp --dport 443 -j ACCEPT").c_str());

    logExam("Online network enabled for " + username);
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

    string allowLoop =
        "iptables -A OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -o lo -j ACCEPT";

    string dropAll =
        "iptables -A OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -j DROP";

    system(allowLoop.c_str());
    system(dropAll.c_str());

    logExam("Network restricted for " + username);
}

void cleanupNetworkRestriction(const string& username)
{
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return;

    int uid = pw->pw_uid;

    string remove1 =
        "iptables -D OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -o lo -j ACCEPT 2>/dev/null";

    string remove2 =
        "iptables -D OUTPUT -m owner --uid-owner " +
        to_string(uid) + " -j DROP 2>/dev/null";

    system(remove1.c_str());
    system(remove2.c_str());
}

/* =========================
   USB STORAGE
   ========================= */

void disableUSB()
{
    system("modprobe -r usb_storage");
    logExam("USB storage disabled");
}

void enableUSB()
{
    system("modprobe usb_storage");
}

/* =========================
   RESOURCE LIMITS
   ========================= */

void applyResourceLimits(const string& username, Mode mode)
{
    string procLimit;

    switch(mode)
    {
        case DEV:     procLimit = "1500"; break;
        case SECURE:  procLimit = "1200"; break;
        case PRIVACY: procLimit = "1200"; break;
        case EXAM:    procLimit = "800";  break;
        default: return;
    }

    ofstream limits("/etc/security/limits.conf", ios::app);

    limits << username << " soft nproc " << procLimit << endl;
    limits << username << " hard nproc " << procLimit << endl;
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

void enableRamHome(const string& username)
{
    string home = "/home/" + username;

    string cmd =
        "mount -t tmpfs -o size=2G tmpfs " + home;

    system(cmd.c_str());

    logExam("RAM home enabled for " + username);
}

void disableRamHome(const string& username)
{
    string cmd =
        "umount -l /home/" + username + " 2>/dev/null";

    system(cmd.c_str());
}

/* DNS privacy */

void applyPrivacyDNS()
{
    ofstream dns("/etc/resolv.conf");

    dns << "nameserver 1.1.1.1\n";
    dns << "nameserver 1.0.0.1\n";
}

/* block telemetry */

void blockTelemetry()
{
    ofstream hosts("/etc/hosts", ios::app);

    hosts << "\n# Vanish privacy block\n";
    hosts << "0.0.0.0 google-analytics.com\n";
    hosts << "0.0.0.0 www.google-analytics.com\n";
    hosts << "0.0.0.0 telemetry.microsoft.com\n";
}

/* cleanup traces */

void cleanupUserTraces(const string& username)
{
    string home = "/home/" + username;

    system(("rm -rf " + home + "/.cache").c_str());
    system(("rm -f " + home + "/.bash_history").c_str());
}

/* =========================
   APPLY POLICIES
   ========================= */

void applyPolicies(const string& username, Mode mode)
{
    applyResourceLimits(username, mode);

    if (mode == EXAM)
    {
        applyNetworkRestriction(username);
        disableUSB();
        setupExamPersistence(username);

        logExam("EXAM mode applied to " + username);
    }

    if (mode == ONLINE) {

        loadOnlineConfig();

        applyOnlineNetwork(username);
        applyOnlineDNSFiltering();
        disableUSB();
        setupExamPersistence(username);

        logExam("ONLINE EXAM mode applied to " + username);
    }

    if (mode == PRIVACY)
    {
        enableRamHome(username);
        applyPrivacyDNS();
        blockTelemetry();

        string themeCmd =
            "sudo -u " + username +
            " dbus-launch gsettings set "
            "org.gnome.desktop.interface color-scheme 'prefer-dark'";

        system(themeCmd.c_str());

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

    enableUSB();

    string unmountCmd =
        "umount -l /home/" + username + "/submit 2>/dev/null";

    system(unmountCmd.c_str());

    logExam("Cleanup completed for " + username);
}
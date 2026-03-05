#include "policy_enforcer.h"
#include <pwd.h>
#include <cstdlib>
#include <fstream>

using namespace std;

Mode parseMode(const string& modeStr) {
    if (modeStr == "dev") return DEV;
    if (modeStr == "secure") return SECURE;
    if (modeStr == "privacy") return PRIVACY;
    if (modeStr == "exam") return EXAM;
    return INVALID;
}

void applyNetworkRestriction(const string& username) {

    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return;

    int uid = pw->pw_uid;

    string allowLoop =
        "iptables -C OUTPUT -m owner --uid-owner " + to_string(uid) +
        " -o lo -j ACCEPT 2>/dev/null || "
        "iptables -A OUTPUT -m owner --uid-owner " + to_string(uid) +
        " -o lo -j ACCEPT";

    string dropAll =
        "iptables -C OUTPUT -m owner --uid-owner " + to_string(uid) +
        " -j DROP 2>/dev/null || "
        "iptables -A OUTPUT -m owner --uid-owner " + to_string(uid) +
        " -j DROP";

    system(allowLoop.c_str());
    system(dropAll.c_str());
}

void cleanupNetworkRestriction(const string& username) {

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

void applyResourceLimits(const string& username, Mode mode) {

    string procLimit;

    switch(mode) {
        case DEV:     procLimit = "1500"; break;
        case SECURE:  procLimit = "1200"; break;
        case PRIVACY: procLimit = "1200"; break;
        case EXAM:    procLimit = "800";  break;
        default: return;
    }

    ofstream limits("/etc/security/limits.conf", ios::app);

    limits << username << " soft nproc " << procLimit << "\n";
    limits << username << " hard nproc " << procLimit << "\n";

    limits.close();
}

void applyPolicies(const string& username, Mode mode) {

    applyResourceLimits(username, mode);

    if (mode == EXAM) {
        applyNetworkRestriction(username);
    }

    if (mode == PRIVACY) {
        string themeCmd =
            "sudo -u " + username +
            " dbus-launch gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark'";
        system(themeCmd.c_str());
    }
}

void cleanupPolicies(const string& username) {
    cleanupNetworkRestriction(username);
}
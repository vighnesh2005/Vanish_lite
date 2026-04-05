#ifndef POLICY_ENFORCER_H
#define POLICY_ENFORCER_H

#include <string>
#include <vector>

enum Mode {
    DEV,
    SECURE,
    PRIVACY,
    EXAM,
    INVALID,
    ONLINE
};

struct PolicyConfig {
    bool exam_restrict_network = true;
    bool exam_disable_usb = true;
    bool exam_enable_persistence = true;

    bool online_enable_network = true;
    bool online_enable_dns_filtering = true;
    bool online_disable_usb = true;
    bool online_enable_persistence = true;
    bool online_enable_command_restriction = false;

    bool privacy_enable_ram_home = true;
    long privacy_ram_home_size_mb = 2048;
    bool privacy_enable_privacy_dns = true;
    bool privacy_block_telemetry = true;
    bool privacy_apply_dark_theme = true;

    long proc_limit_override = -1;

    std::vector<std::string> online_allowed_sites;
    std::vector<std::string> online_blocked_sites;
    std::vector<std::string> online_blocked_commands;
};

Mode parseMode(const std::string& modeStr);

PolicyConfig loadPolicyConfigFile(const std::string& path);

void applyPolicies(const std::string& username, Mode mode, const PolicyConfig& config);

void cleanupPolicies(const std::string& username);



#endif

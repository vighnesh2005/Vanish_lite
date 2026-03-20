#ifndef POLICY_ENFORCER_H
#define POLICY_ENFORCER_H

#include <string>

enum Mode {
    DEV,
    SECURE,
    PRIVACY,
    EXAM,
    INVALID,
    ONLINE
};

Mode parseMode(const std::string& modeStr);

void applyPolicies(const std::string& username, Mode mode);

void cleanupPolicies(const std::string& username);



#endif
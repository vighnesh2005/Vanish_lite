#ifndef SESSION_H
#define SESSION_H

#include "policy_enforcer.h"
#include <string>

void createSession(Mode mode, const std::string& username, const std::string& password, const PolicyConfig& config, bool persistUntilShutdown);
void stopSession();

#endif

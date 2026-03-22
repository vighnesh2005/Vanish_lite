#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <string>
#include <vector>

struct SessionInfo {
    std::string username;
    std::string mode;
    long start_time;
    long last_active;
    long duration;
    bool persist_until_shutdown = false;
};

void createSessionRecord(const std::string& username, const std::string& mode, bool persistUntilShutdown);
void deleteSessionRecord(const std::string& username);
void updateSessionActivity(const std::string& username);

std::vector<SessionInfo> getActiveSessions();

void cleanupExpiredSessions(long logoutTimeout, long examDuration);

#endif

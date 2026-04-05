#include "session_manager.h"
#include "policy_enforcer.h"
#include "utils.h"

#include <fstream>
#include <filesystem>
#include <sstream>
#include <regex>
#include <set>

using namespace std;

const string SESSION_DIR = "/var/vanish_sessions/";
const string MANAGED_USERS_FILE = "/var/vanish_sessions/.managed_users";

/* -------------------------
   CREATE SESSION RECORD
------------------------- */

void createSessionRecord(const string& username, const string& mode, bool persistUntilShutdown){

    filesystem::create_directories(SESSION_DIR);

    string path = SESSION_DIR + username;

    ofstream file(path);

    long now = getCurrentTimestamp();

    file << "username=" << username << endl;
    file << "mode=" << mode << endl;
    file << "start_time=" << now << endl;
    file << "last_active=" << now << endl;
    file << "duration=7200" << endl; // default 2 hours
    file << "persist_until_shutdown=" << (persistUntilShutdown ? "1" : "0") << endl;

    file.close();
}

/* -------------------------
   DELETE SESSION RECORD
------------------------- */

void deleteSessionRecord(const string& username){

    string path = SESSION_DIR + username;

    if(filesystem::exists(path))
        filesystem::remove(path);
}

/* -------------------------
   UPDATE ACTIVITY
------------------------- */

void updateSessionActivity(const string& username){

    string path = SESSION_DIR + username;

    if(!filesystem::exists(path))
        return;

    ifstream in(path);

    vector<string> lines;
    string line;

    while(getline(in, line)){
        lines.push_back(line);
    }

    in.close();

    long now = getCurrentTimestamp();

    for(string &l : lines){

        if(l.find("last_active=") == 0){
            l = "last_active=" + to_string(now);
        }
    }

    ofstream out(path);

    for(string &l : lines)
        out << l << endl;

    out.close();
}

/* -------------------------
   READ SESSION FILE
------------------------- */

SessionInfo parseSessionFile(const string& path){

    SessionInfo info;

    ifstream file(path);

    string line;

    while(getline(file, line)){

        if(line.find("username=") == 0)
            info.username = line.substr(9);

        else if(line.find("mode=") == 0)
            info.mode = line.substr(5);

        else if(line.find("start_time=") == 0)
            info.start_time = stol(line.substr(11));

        else if(line.find("last_active=") == 0)
            info.last_active = stol(line.substr(12));

        else if(line.find("duration=") == 0)
            info.duration = stol(line.substr(9));

        else if(line.find("persist_until_shutdown=") == 0)
            info.persist_until_shutdown = (line.substr(23) == "1");
    }

    return info;
}

/* -------------------------
   LIST ACTIVE SESSIONS
------------------------- */

vector<SessionInfo> getActiveSessions(){

    vector<SessionInfo> sessions;

    if(!filesystem::exists(SESSION_DIR))
        return sessions;

    for(auto &entry : filesystem::directory_iterator(SESSION_DIR)){
        string name = entry.path().filename().string();
        static const regex userPattern("^[a-z_][a-z0-9_-]{0,30}$");
        if (!regex_match(name, userPattern)) {
            continue;
        }
        sessions.push_back(parseSessionFile(entry.path()));
    }

    return sessions;
}

/* -------------------------
   CLEANUP EXPIRED SESSIONS
------------------------- */

void cleanupExpiredSessions(long logoutTimeout, long examDuration){

    vector<SessionInfo> sessions = getActiveSessions();

    long now = getCurrentTimestamp();

    set<string> usersToDelete;

    for(auto &s : sessions){

        bool logoutExpired =
            (now - s.last_active) > logoutTimeout;

        bool examExpired =
            (now - s.start_time) > examDuration;

        if (s.persist_until_shutdown) {
            logoutExpired = false;
            examExpired = false;
        }

        if(logoutExpired || examExpired){
            usersToDelete.insert(s.username);
        }
    }

    for (const auto& user : usersToDelete) {
        cleanupPolicies(user);
        system(("pkill -9 -u " + user + " 2>/dev/null").c_str());
        system(("loginctl terminate-user " + user + " 2>/dev/null").c_str());
        system(("umount -l /home/" + user + "/submit 2>/dev/null").c_str());
        system(("userdel -f -r " + user + " 2>/dev/null").c_str());

        deleteSessionRecord(user);
        filesystem::remove(SESSION_DIR + user + ".policy.conf");
        filesystem::remove(SESSION_DIR + user + ".online.conf");
        filesystem::remove(SESSION_DIR + user + ".monitor.conf");
        filesystem::remove(SESSION_DIR + user + ".limits.intent");
        filesystem::remove(SESSION_DIR + user + ".report.json");

        // Remove user from managed registry.
        if (filesystem::exists(MANAGED_USERS_FILE)) {
            ifstream in(MANAGED_USERS_FILE);
            vector<string> keep;
            string line;
            while (getline(in, line)) {
                if (line != user && !line.empty()) keep.push_back(line);
            }
            ofstream out(MANAGED_USERS_FILE);
            for (const auto& entry : keep) out << entry << "\n";
        }

        writeLog("Session expired and removed: " + user);
    }
}

#include "session_manager.h"
#include "utils.h"

#include <fstream>
#include <filesystem>
#include <sstream>

using namespace std;

const string SESSION_DIR = "/var/vanish_sessions/";

/* -------------------------
   CREATE SESSION RECORD
------------------------- */

void createSessionRecord(const string& username, const string& mode){

    filesystem::create_directories(SESSION_DIR);

    string path = SESSION_DIR + username;

    ofstream file(path);

    long now = getCurrentTimestamp();

    file << "username=" << username << endl;
    file << "mode=" << mode << endl;
    file << "start_time=" << now << endl;
    file << "last_active=" << now << endl;
    file << "duration=7200" << endl; // default 2 hours

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

    for(auto &s : sessions){

        bool logoutExpired =
            (now - s.last_active) > logoutTimeout;

        bool examExpired =
            (now - s.start_time) > examDuration;

        if(logoutExpired || examExpired){

            string cmd =
            "pkill -u " + s.username + " 2>/dev/null";

            system(cmd.c_str());

            cmd = "userdel -r " + s.username + " 2>/dev/null";

            system(cmd.c_str());

            deleteSessionRecord(s.username);

            writeLog("Session expired and removed: " + s.username);
        }
    }
}
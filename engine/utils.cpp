#include "utils.h"

#include <pwd.h>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <regex>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

/* -------------------------
   USER UTILITIES
------------------------- */

bool fileExists(const string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

/* =========================
   INITIALIZE SYSTEM
   ========================= */

void initializeVanishSystem() {

    /* create required directories */

    system("mkdir -p /var/vanish_sessions");
    system("mkdir -p /var/vanish_exam_submissions");

    /* =========================
       CREATE LOG FILE
       ========================= */

    ofstream log("/var/log/vanish_exam.log", ios::app);
    log.close();

    /* =========================
       SET PERMISSIONS
       ========================= */

    system("chmod 700 /var/vanish_sessions");
    system("chmod 700 /var/vanish_exam_submissions");

    system("chmod 644 /var/log/vanish_exam.log");

    /* =========================
       OWNERSHIP (ROOT)
       ========================= */

    system("chown root:root /var/vanish_sessions");
    system("chown root:root /var/vanish_exam_submissions");
}

bool userExists(const string& username) {

    struct passwd *pw = getpwnam(username.c_str());

    return pw != nullptr;
}



string generateUsername() {

    srand(time(nullptr));

    while(true){

        int token = rand() % 100000;

        string username = "vanish_" + to_string(token);

        if(!userExists(username))
            return username;
    }
}

/* -------------------------
   TIME UTILITIES
------------------------- */

long getCurrentTimestamp(){

    return time(nullptr);
}

/* -------------------------
   LOGGING
------------------------- */

void writeLog(const string& message){

    ofstream log("/var/log/vanish_exam.log", ios::app);

    if(!log)
        return;

    time_t now = time(nullptr);

    log << "[" << ctime(&now) << "] " << message << endl;
}

/* -------------------------
   SESSION UTILITIES
------------------------- */

vector<string> listVanishUsers(){

    vector<string> users;
    const string sessionDir = "/var/vanish_sessions";
    static const regex userPattern("^[a-z_][a-z0-9_-]{0,30}$");

    if (!filesystem::exists(sessionDir)) {
        return users;
    }

    for (const auto& entry : filesystem::directory_iterator(sessionDir)) {
        if (!entry.is_regular_file()) continue;
        string name = entry.path().filename().string();
        if (regex_match(name, userPattern)) {
            users.push_back(name);
        }
    }

    return users;
}

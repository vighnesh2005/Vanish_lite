#include "utils.h"

#include <pwd.h>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <sstream>
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

    system("mkdir -p /etc/vanish");
    system("mkdir -p /var/vanish_sessions");
    system("mkdir -p /var/vanish_exam_submissions");

    /* =========================
       CREATE DEFAULT CONFIG
       ========================= */

    if (!fileExists("/etc/vanish/monitor.conf")) {

        ofstream config("/etc/vanish/monitor.conf");

        config << "# ======================\n";
        config << "# VANISH MONITOR CONFIG\n";
        config << "# ======================\n\n";

        config << "# BANNED COMMANDS\n";
        config << "cmd:curl\n";
        config << "cmd:wget\n";
        config << "cmd:python\n";
        config << "cmd:python3\n";
        config << "cmd:git\n";
        config << "cmd:gcc\n";
        config << "cmd:g++\n";
        config << "cmd:node\n\n";

        config << "# BANNED WEBSITES\n";
        config << "site:chat.openai.com\n";
        config << "site:stackoverflow.com\n";
        config << "site:github.com\n\n";

        config.close();
    }

    if (!fileExists("/etc/vanish/online.conf")) {
        ofstream config("/etc/vanish/online.conf");

        config << "# Allowed sites\n";
        config << "allow:docs.python.org\n";
        config << "allow:cplusplus.com\n\n";

        config << "# Blocked sites\n";
        config << "block:chat.openai.com\n";
        config << "block:stackoverflow.com\n";
        config << "block:github.com\n";

        config.close();
    }   

    /* =========================
       CREATE LOG FILE
       ========================= */

    ofstream log("/var/log/vanish_exam.log", ios::app);
    log.close();

    /* =========================
       SET PERMISSIONS
       ========================= */

    system("chmod 700 /etc/vanish");
    system("chmod 600 /etc/vanish/monitor.conf 2>/dev/null");

    system("chmod 700 /var/vanish_sessions");
    system("chmod 700 /var/vanish_exam_submissions");

    system("chmod 644 /var/log/vanish_exam.log");

    /* =========================
       OWNERSHIP (ROOT)
       ========================= */

    system("chown root:root /etc/vanish");
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
   FILE UTILITIES
------------------------- */

bool fileExists(const string& path){

    return filesystem::exists(path);
}

/* -------------------------
   SESSION UTILITIES
------------------------- */

vector<string> listVanishUsers(){

    vector<string> users;

    ifstream passwd("/etc/passwd");

    string line;

    while(getline(passwd, line)){

        if(line.find("vanish_") == 0){

            string username = line.substr(0, line.find(":"));

            users.push_back(username);
        }
    }

    return users;
}
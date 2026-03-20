#include "session.h"
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <pwd.h>
#include "session_manager.h"
#include "utils.h"

using namespace std;


string getUsernameInput(){

    string username;

    cout << "Enter username (leave empty for auto): ";
    getline(cin, username);

    if(username.empty()){
        return generateUsername();
    }

    if(userExists(username)){
        cout << "Username already exists.\n";
        exit(1);
    }

    return username;
}

string getPassword(){

    string pass1, pass2;

    cout << "Enter password: ";
    getline(cin, pass1);

    cout << "Confirm password: ";
    getline(cin, pass2);

    if(pass1 != pass2){
        cout << "Passwords do not match.\n";
        exit(1);
    }

    return pass1;
}
void createSession(Mode mode) {

    string username = generateUsername();
    
    cout << "[INFO] Creating user: " << username << endl;

    string addUserCmd = "useradd -m -s /bin/bash " + username;

    if(system(addUserCmd.c_str()) != 0){
        cerr << "Failed to create user.\n";
        exit(1);
    }

    string passwordCmd = "echo '" + username + ":temporary_user' | chpasswd";
    system(passwordCmd.c_str());

    applyPolicies(username, mode);

    /* create session record */

    string modeStr;

    switch(mode){
        case DEV: modeStr = "dev"; break;
        case SECURE: modeStr = "secure"; break;
        case PRIVACY: modeStr = "privacy"; break;
        case EXAM: modeStr = "exam"; break;
        default: modeStr = "unknown";
    }

    createSessionRecord(username, modeStr);

    cout << "\n=====================================\n";
    cout << "Vanish user created.\n";
    cout << "Username: " << username << endl;
    cout << "Password: temporary_user\n";
    cout << "Mode applied successfully.\n";
    cout << "=====================================\n";
}

#include <filesystem>

void stopSession() {

    system(
        "awk -F: '/^vanish_/ {print $1}' /etc/passwd | "
        "while read u; do "
        "pkill -u $u 2>/dev/null; "
        "umount -l /home/$u/submit 2>/dev/null; "
        "userdel -r $u 2>/dev/null; "
        "done"
    );

    cout << "[INFO] Cleanup completed.\n";
}
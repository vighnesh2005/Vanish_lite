#include "session.h"
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <fstream>

using namespace std;

string generateUsername() {
    srand(time(nullptr));
    int token = rand() % 100000;
    return "vanish_" + to_string(token);
}

void createSession(Mode mode) {

    string username = generateUsername();

    cout << "[INFO] Creating RAM-backed user: " << username << endl;

    string addUserCmd = "useradd -m -s /bin/bash " + username;
    if(system(addUserCmd.c_str()) != 0){
        cerr << "Failed to create user.\n";
        exit(1);
    }

    string passwordCmd = "echo '" + username + ":temporary_user' | chpasswd";
    system(passwordCmd.c_str());

    applyPolicies(username, mode);

    cout << "\n=====================================\n";
    cout << "Vanish user created.\n";
    cout << "Username: " << username << endl;
    cout << "Password: temporary_user\n";
    cout << "Mode applied successfully.\n";
    cout << "=====================================\n";
}

void stopSession() {

    system("awk -F: '/^vanish_/ {print $1}' /etc/passwd | "
           "while read u; do "
           "pkill -u $u 2>/dev/null; "
           "umount /home/$u 2>/dev/null; "
           "userdel -r $u 2>/dev/null; "
           "done");

    cout << "[INFO] Cleanup completed.\n";
}
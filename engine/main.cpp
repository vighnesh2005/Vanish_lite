#include <iostream>
#include <unistd.h>
#include "session.h"
#include "session_manager.h"
#include <vector>
#include "utils.h"

using namespace std;

void showStatus(){

    std::vector<SessionInfo> sessions = getActiveSessions();

    if(sessions.empty()){
        std::cout << "No active sessions.\n";
        return;
    }

    std::cout << "\nActive Sessions\n";
    std::cout << "-----------------------------------\n";

    long now = getCurrentTimestamp();

    for(auto &s : sessions){

        long minutes = (now - s.start_time) / 60;

        std::cout
        << s.username << "   "
        << s.mode << "   "
        << minutes << " min\n";
    }

    std::cout << std::endl;
}

int main(int argc, char* argv[]) {

    if (geteuid() != 0) {
        cout << "Run as root (sudo)\n";
        return 1;
    }

    if (argc < 2) {
        cout << "Usage:\n";
        cout << "  sudo vanish start <mode>\n";
        cout << "  sudo vanish stop\n";
        cout << "  sudo vanish status\n";
        cout << "Modes: dev | secure | privacy | exam\n";
        return 1;
    }

    string command = argv[1];

    if (command == "start") {

        if (argc < 3) {
            cout << "Missing mode.\n";
            cout << "Modes: dev | secure | privacy | exam\n";
            return 1;
        }

        string modeStr = argv[2];
        Mode mode = parseMode(modeStr);

        if (mode == INVALID) {
            cout << "Invalid mode.\n";
            return 1;
        }

        createSession(mode);
    }
    else if (command == "stop") {

        stopSession();
    }
    else if (command == "status") {

        showStatus();
    }
    else {

        cout << "Invalid command.\n";
    }
    return 0;
}
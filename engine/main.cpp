#include <iostream>
#include <unistd.h>
#include "session.h"

using namespace std;

int main(int argc, char* argv[]) {

    if (geteuid() != 0) {
        cout << "Run as root (sudo)\n";
        return 1;
    }

    if (argc < 2) {
        cout << "Usage:\n";
        cout << "  sudo vanish start <mode>\n";
        cout << "  sudo vanish stop\n";
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
    else {
        cout << "Invalid command.\n";
    }

    return 0;
}
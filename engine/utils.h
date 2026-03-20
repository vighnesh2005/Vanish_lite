#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

//initialize the vanish system (create log file, setup directories, etc)
void initializeVanishSystem();

/* user utilities */

bool userExists(const std::string& username);
std::string generateUsername();

/* time utilities */

long getCurrentTimestamp();

/* logging */

void writeLog(const std::string& message);

/* file utilities */

bool fileExists(const std::string& path);

/* session utilities */

std::vector<std::string> listVanishUsers();

#endif
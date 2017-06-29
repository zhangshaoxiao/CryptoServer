#include<string>
//using namespace std;
#ifndef mySHA_H
#define mySHA_H

void CalculateDigest(std::string &Digest, const std::string &Message);
bool VerifyDigest(const std::string &Digest, const std::string &Message);
#endif


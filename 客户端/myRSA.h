#include<string>
#ifndef myRSA_H
#define myRSA_H
std::string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);
void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed); //…˙≥…√‹‘ø
int CRYPTOPP_API CroptoPP(int argc, char *argv[]);
void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename);
bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename);

//string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);
#endif


#include "Winsock2.h"  
#include<string>
#define MAX 1024
#ifndef Server_H
#define Server_H
struct UserInfo       //每一个连接上的用户信息
{
	char Name[MAX];   //账号
	SOCKADDR_IN addr_Clt;  //IP地址
};
int   Login(UserInfo Client[20]);

#endif

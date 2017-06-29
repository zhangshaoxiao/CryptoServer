#define HAVE_STRUCT_TIMESPEC
#include "Winsock2.h"  
#include"SHA.h"
#include <windows.h> 
#include <math.h> 
#include <process.h>  
#include<stdio.h>
#include <WS2tcpip.h>
#include "string"  
#include<pthread.h>

#include<rsa.h>
#include"myRSA.h"
#include"mySHA.h"
#include"myAES.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "pthreadVC2.lib")
#pragma comment(lib,"Msimg32.lib")
#define MAX 1024
#define HOST_IP "127.0.0.1"  
#define OK_STR "连接服务器成功"  
#define ERROR "密码错误"
#define NOT_FIND "查无此人"
#define MSG_HOST_PORT 8080  
#define LOGIN_HOST_PORT 8081  
#define CLIENT_PORT  8088
#define LOGIN 1                 //消息类型标记 ，1代表登录信息，2代表是消息， 3代表是新用户上线通知
#define MSG 2
#define NEW_USR 3
char UserName[MAX];
char PassWord[MAX];
char cRecvBuf[MAX];
//string aesKey = "0123456789ABCDEF0123456789ABCDEF";//256bits, also can be 128 bits or 192bits  
struct UserInfo       //每一个连接上的用户信息
{
	char Name[MAX];   //账号
	SOCKADDR_IN addr_Clt;  //IP地址
};
using namespace std;
string aesKey = "0123456789ABCDEF0123456789ABCDEF";//256bits, also can be 128 bits or 192bits  
void * Listen_Server(void *ptr);    //向服务器发送登录请求，并且另开线程监听服务器发回来的消息
void * Listen_OtherClient(void *ptr);
UserInfo Client[20];
int main()
{
	
	cout << "输入Y/N选择是否重新产生一组RSA公钥密钥\n";
	char OP;
	cin >> OP;
	if (OP == 'Y')
	{
		char thisSeed[1024], privFilename[128], pubFilename[128];
		unsigned int keyLength;
		cout << "Key length in bits: ";
		cin >> keyLength;

		cout << "\nSave private key to file: ";
		cin >> privFilename;

		cout << "\nSave public key to file: ";
		cin >> pubFilename;

		cout << "\nRandom Seed: ";
		ws(cin);
		cin.getline(thisSeed, 1024);
		GenerateRSAKey(keyLength, privFilename, pubFilename, thisSeed);
	}
	
	char Message[MAX];
	cout << "输入登录帐号" << endl;
	//scanf_s("%s,%s", &UserName, &PassWord);
	cin >> UserName;
	cout << "输入登录密码" << endl;
	cin >> PassWord;
	
	pthread_t RECV_Server;                //创建线程接收消息
	pthread_create(&RECV_Server, NULL, Listen_Server, 0); //为了使界面不卡死，我们使用多线程
	//pthread_t RECV_Other;
	//pthread_create(&RECV_Other, NULL, Listen_OtherClient, 0);
	
	int version_a = 1;//low bit                    这部分用来发送消息 
	int version_b = 1;//high bit  
					  //makeword  
	WORD versionRequest = MAKEWORD(version_a, version_b);
	WSAData wsaData;
	int error;
	error = WSAStartup(versionRequest, &wsaData);

	if (error != 0) {
		printf("ERROR!");

	}
	//check whether the version is 1.1, if not print the error and cleanup wsa?  
	if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1)
	{
		printf("WRONG WINSOCK VERSION!");
		WSACleanup();

	}
	char requestStr[MAX];
	SOCKET MSGsocClient;
	SOCKADDR_IN MSGaddrSrv;
	//build a sockeet   
	MSGsocClient = socket(AF_INET, SOCK_DGRAM, 0);
	MSGaddrSrv;        // a instance of SOCKADDR_IN, which is used in format of SOCKADDR.  
	inet_pton(AF_INET, "127.0.0.1", (void *)&MSGaddrSrv.sin_addr.S_un.S_addr);        //set the host IP  
	MSGaddrSrv.sin_family = AF_INET;     //set the protocol family  
	MSGaddrSrv.sin_port = htons(MSG_HOST_PORT);      //set the port number  

													 // array to store the data that server feedback.  
	char cSendBuf[MAX];
	char EncryptMSG[MAX];
	int fromlen = sizeof(SOCKADDR);
	while (true)
	{
		cout << "请输入发送内容\n" << endl;
		cin >> cSendBuf;
		string Encry = ECB_AESEncryptStr(aesKey,cSendBuf);
		strcpy_s(EncryptMSG,MAX, Encry.c_str());
		sendto(MSGsocClient, EncryptMSG, strlen(EncryptMSG) + 1, 0, (SOCKADDR*)&MSGaddrSrv, sizeof(SOCKADDR));
		
	}


}


void * Listen_Server(void *ptr)
{
	int ch;
	char Cname[MAX];
	char Cip[MAX];
	int Client_Num = 0;

	
	int version_a = 1;//low bit  
	int version_b = 1;//high bit  
					  //makeword  
	WORD versionRequest = MAKEWORD(version_a, version_b);
	WSAData wsaData;
	int error;
	error = WSAStartup(versionRequest, &wsaData);

	if (error != 0) {
		printf("ERROR!");

	}
	//check whether the version is 1.1, if not print the error and cleanup wsa?  
	if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1)
	{
		printf("WRONG WINSOCK VERSION!");
		WSACleanup();

	}
	char requestStr[MAX];
	SOCKET socClient;
	SOCKADDR_IN addrSrv;
	//build a sockeet   
	socClient = socket(AF_INET, SOCK_DGRAM, 0);
       // a instance of SOCKADDR_IN, which is used in format of SOCKADDR.  
	inet_pton(AF_INET, "127.0.0.1", (void *)&addrSrv.sin_addr.S_un.S_addr);        //set the host IP  
	addrSrv.sin_family = AF_INET;     //set the protocol family  
	addrSrv.sin_port = htons(LOGIN_HOST_PORT);      //set the port number  

													// array to store the data that server feedback.  
	
	int fromlen = sizeof(SOCKADDR);
	sendto(socClient, ECB_AESEncryptStr(aesKey, UserName).c_str(), strlen(ECB_AESEncryptStr(aesKey, UserName).c_str()) + 1, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	Sleep(500);
	sendto(socClient, ECB_AESEncryptStr(aesKey, PassWord).c_str(), strlen(ECB_AESEncryptStr(aesKey, PassWord).c_str()) + 1, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	//addrSrv.sin_port = htons(MSG_HOST_PORT);      //set the port number  
	char DecryptMSG[MAX];
	FILE *log;   //写日志
	FILE *READ;
	string Digest;
	
	string Sign;
	char Rstr[MAX * 5];

	cout << "聆听服务器消息线程启动成功\n";
	while (true)
	{
		for (ch = 0; ch < MAX; ch++)
		{
			Cname[ch] = '\0';
			Cip[ch] = '\0';
		}
		recv(socClient, cRecvBuf, MAX, 0);	 
		string  De = ECB_AESDecryptStr(aesKey, cRecvBuf);
		fopen_s(&log,"log.txt", "a+");
		 fputs(cRecvBuf, log);
		 fputc('\n', log);
		 fclose(log);   
		 
		 fopen_s(&READ, "log.txt","r");
		 fread(Rstr, 5*MAX, 1,READ);
		                                   //产生HASH
		 fclose(READ);
		 CalculateDigest(Digest, (string)Rstr);
		 Sign= ECB_AESEncryptStr(aesKey,Digest.c_str());  //j加密HASH值
		 fopen_s(&READ, "sign.txt", "w");
		 fputs(Sign.c_str(),READ);
		 fclose(READ);                 //写签名到文件
		 
	//	 RSASignFile("pri", "log.txt","RSASign");
		//cout <<"mes"<< ECB_AESDecryptStr(aesKey,cRecvBuf) << endl;   //解密
		
		 strcpy_s(DecryptMSG, MAX, De.c_str());
		//strcpy_s(DecryptMSG, sizeof(De.c_str()), De.c_str());
		cout <<"message:"<< De.c_str() << endl;
		
		if(strcmp(De.c_str(),OK_STR)==0)
		    cout <<"连接服务器成功  \n" << endl;
		else if(strcmp(De.c_str(), ERROR) == 0)
			cout << "密码错误  \n"  << endl;
		else if (strcmp(De.c_str(), NOT_FIND) == 0)
			cout << "查无此人  \n" << endl;
			
		else if(DecryptMSG[0]=='!')
		{

			for (ch = 1; DecryptMSG[ch] != '#'; ch++)
			{
				Cname[ch] = DecryptMSG[ch];
			}
			int hhh = 0;
			for (ch=ch+1; ch < strlen(DecryptMSG); ch++)
			{
				Cip[hhh] = DecryptMSG[ch];
				hhh++;
			}
			//strcpy_s(Client[Client_Num].Name, strlen(Cname), Cname);
			for (int fff = 0; fff < strlen(Cname); fff++)
			{
				Client[Client_Num].Name[fff] = Cname[fff];
			} 
			//Client[Client_Num].addr_Clt.sin_addr = inet_pton((int)Cip);
			inet_pton(AF_INET, Cip, &Client[Client_Num].addr_Clt.sin_addr);//把字符串转换成IP
			Client[Client_Num].addr_Clt.sin_port = MSG_HOST_PORT;

		}
		else
		{
			cout << "新消息: " << DecryptMSG << endl;
		}
		
	}
}

void * Listen_OtherClient(void *ptr)
{
	
	int version_a = 1;//low bit  
	int version_b = 1;//high bit  
					  //makeword  
	WORD versionRequest = MAKEWORD(version_a, version_b);
	WSAData wsaData;
	int error;
	error = WSAStartup(versionRequest, &wsaData);

	if (error != 0) {
		printf("ERROR!");

	}
	//check whether the version is 1.1, if not print the error and cleanup wsa?  
	if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1)
	{
		printf("WRONG WINSOCK VERSION!");
		WSACleanup();

	}
	char requestStr[MAX];
	/*
	SOCKET socClient;
	SOCKADDR_IN addrSrv;
	//build a sockeet   
	socClient = socket(AF_INET, SOCK_DGRAM, 0);
	addrSrv;        // a instance of SOCKADDR_IN, which is used in format of SOCKADDR.  
	inet_pton(AF_INET, "127.0.0.1", (void *)&addrSrv.sin_addr.S_un.S_addr);        //set the host IP  
	addrSrv.sin_family = AF_INET;     //set the protocol family  
	addrSrv.sin_port = htons(CLIENT_PORT);      //set the port number  

													// array to store the data that server feedback.  
*/
	SOCKET socClient = socket(AF_INET, SOCK_DGRAM, 0);
	SOCKADDR_IN addrSrv;        // a instance of SOCKADDR_IN, which is used in format of SOCKADDR.  
	inet_pton(AF_INET, "127.0.0.1", (void *)&addrSrv.sin_addr.S_un.S_addr);        //set the host IP  
	addrSrv.sin_family = AF_INET;     //set the protocol family  
	addrSrv.sin_port = htons(MSG_HOST_PORT);      //set the port number  

	int fromlen = sizeof(SOCKADDR);
	SOCKADDR_IN in_addr;        //接入地址
	
	//addrSrv.sin_port = htons(MSG_HOST_PORT);      //set the port number  
	char DecryptMSG[MAX];
	FILE *log;   //写日志
	char Buf[MAX];
	cout << "聆听消息线程启动成功\n";
	while (true)
	{
		
		
		recv(socClient, Buf, strlen(Buf) + 1, 0);
		fopen_s(&log, "msg.txt", "at+");
		fputs(Buf, log);
		fputc('\n', log);
		fclose(log);                                        //写日志
		RSASignFile("pri", "log.txt", "RSASign.txt");
		//string De = ECB_AESDecryptStr(aesKey, cRecvBuf);   //解密
		cout << "收到一条消息: \n" << ECB_AESDecryptStr(aesKey, Buf) << endl;
		
	}
}
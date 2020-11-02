#ifndef __FRAMEWORK_H__
#define __FRAMEWORK_H__


#include "ore.h"

#include <openssl/rsa.h>



#define TOKEN_CAPACITY 2
#define RSA_LEN 2048
#define LAMBDA 128

#define HASH_SECRET_LEN 32
#define TOKEN_NAME_LEN 100


static unsigned int HashOutputLen = HASH_SECRET_LEN;


typedef struct 
{
	char mName[TOKEN_NAME_LEN];
	unsigned int counter;
	unsigned char latest[RSA_LEN/8];
}TOKEN;



typedef struct {
	TOKEN token[TOKEN_CAPACITY];
	
	unsigned char k0[LAMBDA/8];

	ore_secret_key ore_sk;
	ore_params ore_pk;
	uint32_t cipherBuffLen;


	RSA *rsa;
	// unsigned char rsa_sk[256];
	// unsigned char rsa_pk[256];


	// bool isKSInitaite[TOKEN_CAPACITY];
	unsigned char ks[TOKEN_CAPACITY][HASH_SECRET_LEN];
}clientParameters;






typedef struct {
	unsigned char ks[TOKEN_CAPACITY][LAMBDA/8];

	ore_secret_key ore_sk;
	ore_params ore_pk;
	uint32_t cipherBuffLen;


	RSA *rsa;

	// unsigned char rsa_pk[RSA_LEN/8];
} serverParameters;




typedef struct  
{

  	// int nbits = 31, out_blk_len = ((rand() % (nbits - 2)) + 2);
  	// uint32_t buffLen = (nbits * out_blk_len + 7) / 8;
	//According to ore maximum possible size with current formula limitation.
	//max val is 117.125
	
	unsigned char cipher[120];
	uint32_t index;
}dataItem;



typedef struct  
{
	dataItem data[10];
	uint32_t currentNum;
}DataBase;





#endif /* __FRAMEWORK_H__ */
#include <stdio.h>

# include <openssl/bn.h>
# include <openssl/rsa.h>
# include <openssl/hmac.h>
# include <openssl/kdf.h>

#include "ore.h"
#include "errors.h"
#include "flags.h"
#include "framework.h"


RSA *RSA_generate_keyPairs(int bits)
{
    RSA *rsa = RSA_new();
    BIGNUM *public_key_exponent = BN_new();
    BN_set_word(public_key_exponent, RSA_F4);
    RSA_generate_key_ex(rsa, bits, public_key_exponent, NULL);
    return rsa;
}

static void KDF(unsigned char* secretKey,int keyLen,unsigned char* outPut,int outLength){

     size_t outlen = outLength;

     EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
     EVP_PKEY_derive_init(pctx);

     EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
     EVP_PKEY_CTX_set1_hkdf_salt(pctx, "salt", 4);

     EVP_PKEY_CTX_set1_hkdf_key(pctx,secretKey,keyLen);

     EVP_PKEY_CTX_add1_hkdf_info(pctx, "label", 5);
     EVP_PKEY_derive(pctx, outPut, &outlen);
}

static void xorArray(unsigned char *target,const unsigned char *src,uint32_t len){
  while(len--)
  {
    *target++ ^= *src++;
  }
}


// void printData(unsigned char*data,int len,unsigned char* descInfo){
//     printf("%s:\n",descInfo);


//     uint32_t count = 0;
//     while(count< len){
//     // while(count< client->cipherBuffLen){
//       printf("%02x",*(data+count));
//       // printf("%02x",deriveOutput[count]);
//       count++;
//     }
//     printf("\n\n");
// }

static void decryptCipher(dataItem *c,TOKEN *queryToken,const unsigned char *ks,uint32_t ksLen,serverParameters* server){

  uint32_t cycle = queryToken->counter - c->index;
  unsigned char fromBuffer[RSA_LEN/8];
  unsigned char toBuffer[RSA_LEN/8];

  memcpy(fromBuffer,queryToken->latest,sizeof(queryToken->latest));
  memcpy(toBuffer,queryToken->latest,sizeof(queryToken->latest));

  for (uint32_t i=0;i<cycle;i++){
   RSA_public_decrypt(RSA_LEN/8,fromBuffer,toBuffer,server->rsa,RSA_NO_PADDING);
   memcpy(fromBuffer,toBuffer,sizeof(toBuffer));
  }

  //Generate hashOutput;
  unsigned char hashOutput[HASH_SECRET_LEN];
  HMAC(EVP_sha256(),ks,ksLen,toBuffer,sizeof(toBuffer),hashOutput,&HashOutputLen);


  unsigned char deriveOutput[120];
  KDF(hashOutput,HashOutputLen,deriveOutput,120);
  xorArray(c->cipher,deriveOutput,120);
}


int frameworkEncrypt(clientParameters* client,uint64_t number,char *orderSpaceName,DataBase *db){

  for(int i=0;i<TOKEN_CAPACITY;i++){

   if(strcmp(client->token[i].mName,orderSpaceName) == 0){
      //generate nextToken
      client->token[i].counter++;

      unsigned char temp[RSA_LEN/8];
      memcpy(temp, client->token[i].latest,sizeof(temp));
      RSA_private_encrypt(RSA_LEN/8,temp,client->token[i].latest,client->rsa,RSA_NO_PADDING);

      //ore encrypt  
      ore_ciphertext ctxt1;
      init_ore_ciphertext(ctxt1, client->ore_pk);
      ore_encrypt_ui(ctxt1, client->ore_sk, number);


      // unsigned char ciphertext[HASH_SECRET_LEN];
      if(db->currentNum == 10)
      {
        printf("dataBase is full!\n");
        return -1;
      }


      dataItem *newData = &db->data[db->currentNum];
      memcpy(newData->cipher,ctxt1->buf,client->cipherBuffLen);
      newData->index = client->token[i].counter;
      clear_ore_ciphertext(ctxt1);

      //generate HASH Mask
      unsigned char hashOutput[HashOutputLen];
      HMAC(EVP_sha256(),client->ks[i],sizeof(client->ks[i]),
        client->token[i].latest,sizeof(client->token[i].latest),
        hashOutput,&HashOutputLen);

      unsigned char deriveOutput[120];
      KDF(hashOutput,HashOutputLen,deriveOutput,120);
      xorArray(newData->cipher,deriveOutput,120);
      db->currentNum += 1;
      break;
   }
  }
}


int frameworkCompare(dataItem *c1,dataItem *c2,TOKEN *queryToken,
    const unsigned char *ks, uint32_t ksLen,serverParameters* server)
{
  decryptCipher(c1,queryToken,ks,ksLen,server);
  decryptCipher(c2,queryToken,ks,ksLen,server);

  //Restore ciphertext;  
  ore_ciphertext ctxt1;
  ctxt1->buf = malloc(server->cipherBuffLen);
  memcpy(ctxt1->buf,c1->cipher,server->cipherBuffLen);
  ctxt1->initialized = true;
  init_ore_params(ctxt1->params, server->ore_pk->nbits, server->ore_pk->out_blk_len);

  ore_ciphertext ctxt2;
  ctxt2->buf = malloc(server->cipherBuffLen);
  memcpy(ctxt2->buf,c2->cipher,server->cipherBuffLen);
  ctxt2->initialized = true;
  init_ore_params(ctxt2->params,server->ore_pk->nbits, server->ore_pk->out_blk_len);

  int ret;
  ore_compare(&ret, ctxt1, ctxt2);
  printf("final compare result is: %d\n",ret);

  ore_compare(&ret, ctxt2, ctxt1);
  printf("reversal compare result is: %d\n",ret);

  clear_ore_ciphertext(ctxt1);
  clear_ore_ciphertext(ctxt2);
}



int frameworkSetup(clientParameters* client,serverParameters* server)
{
  //ORE algorithm initiating...
  int nbits = 31, out_blk_len = ((rand() % (nbits - 2)) + 2);
  client->cipherBuffLen = (nbits * out_blk_len + 7) / 8;
  server->cipherBuffLen = client->cipherBuffLen;


  init_ore_params(client->ore_pk, nbits, out_blk_len);
  ore_setup(client->ore_sk, client->ore_pk);
  

   //The token generating algorithm.
   RSA *rsa = RSA_generate_keyPairs(RSA_LEN);
   client->rsa = rsa;


   //Randomly generate main secret key.
   BIGNUM *k0=BN_new();
   BN_rand(k0,LAMBDA,BN_RAND_TOP_ANY,BN_RAND_BOTTOM_ANY);
   BN_bn2binpad(k0,client->k0,LAMBDA/8);


   //Initiate first token...
  for(int i=0;i<TOKEN_CAPACITY;i++){
     BIGNUM *k0=BN_new();
     BN_rand(k0,RSA_LEN,BN_RAND_TOP_ANY,BN_RAND_BOTTOM_ANY);
     BN_bn2binpad(k0,client->token[i].latest,RSA_LEN/8);


    //generate ks using PRF
    HMAC(EVP_sha256(),client->k0,sizeof(client->k0),
      client->token[i].mName,TOKEN_NAME_LEN,
      client->ks[i],&HashOutputLen);
  }


   memcpy(server->ore_pk, client->ore_pk, sizeof(ore_params));
   memcpy(server->ore_sk, client->ore_sk, sizeof(ore_secret_key));
   server->rsa = RSAPublicKey_dup(rsa);

   return 1;	
}



int main(int argc, char** argv){
	char orderingSpace[TOKEN_CAPACITY][TOKEN_NAME_LEN] = {"sellPrice","buyPrice"};

  clientParameters client;

  for(int i=0;i<TOKEN_CAPACITY;i++){
    strcpy(client.token[i].mName,orderingSpace[i]);
    client.token[i].counter = 0;
  }

  serverParameters server;

  //Initiate server database
  DataBase db;
  db.currentNum=0;


	if(frameworkSetup(&client,&server)){

    frameworkEncrypt(&client,523,orderingSpace[0],&db);
    frameworkEncrypt(&client,231,orderingSpace[0],&db);
    frameworkEncrypt(&client,321,orderingSpace[0],&db);


    TOKEN markToken  = client.token[0];

    frameworkEncrypt(&client,421,orderingSpace[0],&db);
    frameworkEncrypt(&client,251,orderingSpace[0],&db); 


    dataItem* cipher1 = &db.data[0];
    dataItem* cipher2 = &db.data[1];

    frameworkCompare(cipher1,cipher2,&markToken,client.ks[0],HASH_SECRET_LEN,&server);
  }

  return 1;
}
//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/rand.h>
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
  //-------------------------------------------------------------------------
  // Initialization
  
  ERR_load_crypto_strings();
  SSL_library_init();
  SSL_load_error_strings();
  
  setbuf(stdout, NULL); // disables buffered output
  
  // Handle commandline arguments
  // Useage: client server:port filename
  if (argc < 3)
    {
      printf("Useage: client -server serveraddress -port portnumber filename\n");
      exit(EXIT_FAILURE);
    }
  char* server = argv[1];
  char* filename = argv[2];
  
  printf("------------\n");
  printf("-- CLIENT --\n");
  printf("------------\n");
  
  //-------------------------------------------------------------------------
  // 1. Establish SSL connection to the server
  printf("1.  Establishing SSL connection with the server...");
  
  // Setup client context
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
    {
      printf("Error setting cipher list. Sad christmas...\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the BIO
  BIO* client = BIO_new_connect(server);
  if (BIO_do_connect(client) != 1)
    {
      printf("FAILURE.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the SSL
  SSL* ssl=SSL_new(ctx);
  if (!ssl)
    {
      printf("Error creating new SSL object from context.\n");
      exit(EXIT_FAILURE);
    }
  SSL_set_bio(ssl, client, client);
  if (SSL_connect(ssl) <= 0)
    {
      printf("Error during SSL_connect(ssl).\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  printf("SUCCESS.\n");
  printf("    (Now connected to %s)\n", server);
  
  //-------------------------------------------------------------------------
  // 2. Send the server a random number
  printf("2.  Sending challenge to the server...");
  
  unsigned char randomNumber[128];//buffer to hold challenge
  memset(randomNumber,0,128);//init buffer
  RAND_bytes(randomNumber,128);//get random challenge
  unsigned char buf[128];//buffer to hold encrypted challenge
  memset(buf,0,sizeof(buf));//init buffer
  BIO *fp=BIO_new_file("rsapublickey.pem","r");//open RSA pub key
  RSA *x;//RSA struct
  x=PEM_read_bio_RSA_PUBKEY(fp,NULL,0,0);//setting RSA
  RSA_public_encrypt(128,randomNumber,buf,x,RSA_NO_PADDING);//encrypt
  SSL_write(ssl,buf,128);//write encryption
  unsigned char hash[128];//buffer for hashing
  memset(hash,0,sizeof(hash));//init buffer
  SHA1((unsigned char*)randomNumber,128,hash);//hash
  printf("SUCCESS.\n");//print hash
  printf("    (Challenge sent: \"%s\")\n", 
	 buff2hex((const unsigned char*)randomNumber,128).c_str());
  
  //-------------------------------------------------------------------------
  // 3a. Receive the signed key from the server
  printf("3a. Receiving signed key from server...");
  
  unsigned char buff[128];//buffer for getting signed key
  memset(buff,0,sizeof(buff));//init buffer
  int len=SSL_read(ssl,buff,128);//read key
  printf("RECEIVED.\n");//print signature
  printf("    (Signature: \"%s\" (%d bytes))\n",
	 buff2hex((const unsigned char*)buff, len).c_str(), len);
  
  //-------------------------------------------------------------------------
  // 3b. Authenticate the signed key
  printf("3b. Authenticating key...");
  unsigned char hashR[128];//buffer for decrpyting hash
  memset(hashR,0,sizeof(hashR));//init buffer
  RSA_public_decrypt(128,buff,hashR,x,RSA_NO_PADDING);//decrypt hash
  
  printf("AUTHENTICATED\n");//print keys
  printf("    (Generated key: %s)\n", buff2hex((const unsigned char*)hash,20).c_str());
  printf("    (Decrypted key: %s)\n", buff2hex((const unsigned char*)hashR,20).c_str());
  
  //-------------------------------------------------------------------------
  // 4. Send the server a file request
  printf("4.  Sending file request to server...");
  SSL_write(ssl,argv[2],BUFFER_SIZE);//write the file name to ther server
  printf("SENT.\n");
  printf("    (File requested: \"%s\")\n", filename);//print filename
  
  //-------------------------------------------------------------------------
  // 5. Receives and displays the contents of the file requested
  printf("5.  Receiving response from server...");
  
  
  unsigned char buffer[BUFFER_SIZE];//buffer for reading from file and sending
  memset(buffer,0,sizeof(buffer));//init buffer
  BIO *writ =BIO_new_file(argv[2],"w");//open BIO file to write to
  cout << endl << "PRINTING FILE CONTENTS:"<< endl;
  while(SSL_read(ssl,buffer,1)>0){//while not empty ssl buffer
    BIO_write(writ,buffer,1);//write a byte to the file
    cout << buffer;//write to the terminal
  }  
  printf("\nFILE RECEIVED.\n");
  
  //-------------------------------------------------------------------------
  // 6. Close the connection
  printf("6.  Closing the connection...");
  SSL_shutdown(ssl);
  printf("DONE.\n");
  printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
  
  //-------------------------------------------------------------------------
  // Freedom!
  SSL_CTX_free(ctx);
  SSL_free(ssl);
  return EXIT_SUCCESS;
  
}

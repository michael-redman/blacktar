#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>

#include <hexbytes.h>

extern int read_whole_file (char const * const, unsigned char **, unsigned int *);

int main (int argc, char ** argv) {
	unsigned char *key;
	unsigned int key_l;
	char data[2*SHA256_DIGEST_LENGTH+2];
	unsigned char *hmac;
	read_whole_file(argv[1],&key,&key_l);
	while	(!feof(stdin)) {
		if (!fgets(data,2*SHA256_DIGEST_LENGTH+2,stdin)) break;
		data[2*SHA256_DIGEST_LENGTH]='\0';
		hmac=HMAC(EVP_sha256(),key,key_l,(unsigned char const *)data,2*SHA256_DIGEST_LENGTH,NULL,NULL);
		hexbytes_print(hmac,SHA256_DIGEST_LENGTH,data);
		puts(data); }
	if (ferror(stdin)) { perror("stdin"); return -1; }
	return 0; }

//IN GOD WE TRVST.

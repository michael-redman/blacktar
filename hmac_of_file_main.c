#include <openssl/engine.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hexbytes.h>

extern void hmac_of_file
        (
                const unsigned char * const key,
                const unsigned int key_len,
                const char * const path,
                unsigned char digest[SHA_DIGEST_LENGTH]);

int main(const int argc, const char ** argv){
	unsigned char hmac_binary[SHA_DIGEST_LENGTH], *key=NULL;
	char hmac_text[2*SHA_DIGEST_LENGTH+1];
	unsigned int bytes_read=0, alloc_size=0;
	FILE *stream;
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
	if	(!(stream=fopen(argv[1],"rb")))
		{ perror(argv[1]); goto err0; }
	while(!feof(stream)){
		if	(bytes_read==alloc_size)
			{
				alloc_size=1+3*alloc_size;
				if
					(!(key=realloc(key,alloc_size)))
					{
						fputs("realloc failed",stderr);
						goto err1; }}
		bytes_read+=fread(&key[bytes_read],1,alloc_size-bytes_read,stream);
		if (ferror(stream)) { perror(argv[1]); goto err1; }}
	hmac_of_file(
		(const unsigned char * const)key,
		bytes_read,
		argv[2],
		hmac_binary);
	free(key);
	if (fclose(stream)) { perror(argv[1]); goto err0; }
	ENGINE_cleanup();
	hexbytes_print(hmac_binary,SHA_DIGEST_LENGTH,hmac_text);
	puts(hmac_text);
	return 0;
	err1:	if (key) free(key);
		if (fclose(stream)) perror(argv[1]);
	err0:	ENGINE_cleanup();
		exit(EXIT_FAILURE); }

/*IN GOD WE TRVST.*/

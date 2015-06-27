#define USE "blacktar_list_cruft 'db conn string' key_file < output_of_s3_list_keys\n"

#include <libpq-fe.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int read_whole_file(char const * const, unsigned char **, unsigned int *);

#define AT fprintf(stderr,"at "__FILE__":%u\n",__LINE__)
#define SQLERR fputs(PQerrorMessage(db),stderr)

#define S3_KEY_MAX_LEN 1024

int compar(const void *a, const void *b){ return memcmp(a,b,2*SHA256_DIGEST_LENGTH); }

int main (int argc, char ** argv) {
	PGconn *db;
	PGresult *result;
	unsigned int key_l, n_alloc=0, n_data=0, tmp0, i;
	char *hmacs=NULL, hmac_text[2*SHA256_DIGEST_LENGTH+2], s3_key[S3_KEY_MAX_LEN+2], *p;
	unsigned char *hmac_binary, *key;
	if (argc!=3) { fputs(USE,stderr); return 1; }
	if (read_whole_file(argv[2],&key,&key_l)) { perror(argv[2]); return 1; }
	db=PQconnectdb(argv[1]);
	if (PQstatus(db)!=CONNECTION_OK){ SQLERR; AT; goto l0; }
	result=PQexec(db,"begin");
	if (PQresultStatus(result)!=PGRES_COMMAND_OK){ SQLERR; AT; goto l1; }
	result=PQexec(db,"declare hashes cursor for select content from inodes where mode/4096=8");
	if (PQresultStatus(result)!=PGRES_COMMAND_OK){ SQLERR; AT; goto l1; }
	PQclear(result);
	while(1){
		result=PQexec(db,"fetch hashes");
		if (PQresultStatus(result)!=PGRES_TUPLES_OK) { SQLERR; AT; goto l1; }
		if (!PQntuples(result)) break;
		hmac_binary=HMAC(EVP_sha256(),key,key_l,(unsigned char const *)PQgetvalue(result,0,0),2*SHA256_DIGEST_LENGTH,NULL,NULL);
		if	(n_alloc==n_data)
			{	n_alloc=1+3*n_alloc;
				hmacs=realloc(hmacs, 2*SHA256_DIGEST_LENGTH*n_alloc);
				if (!hmacs) { fputs("realloc failed\n",stderr); goto l1; }}
		p=&hmacs[2*SHA256_DIGEST_LENGTH*n_data++];
		for	(i=0;i<SHA256_DIGEST_LENGTH;i++)
			sprintf(&p[2*i],"%02hhx",hmac_binary[i]);
		PQclear(result); }
	PQclear(result);
	PQexec(db,"close hashes");
	if (PQresultStatus(result)!=PGRES_COMMAND_OK){ SQLERR; AT; goto l1; }
	PQclear(result);
	PQfinish(db);
	qsort(hmacs,n_data,2*SHA256_DIGEST_LENGTH,compar);
	while	(!feof(stdin))
		{	if (!fgets(s3_key,S3_KEY_MAX_LEN+2,stdin)) break;
			strncpy(hmac_text,s3_key,2*SHA256_DIGEST_LENGTH);
			hmac_text[2*SHA256_DIGEST_LENGTH]='\0';
			tmp0=strlen(hmac_text)-1;
			if (hmac_text[tmp0]=='\n') hmac_text[tmp0]='\0';
			if (!bsearch(hmac_text,hmacs,n_data,2*SHA256_DIGEST_LENGTH,compar)) puts(hmac_text); }
	if (hmacs) free(hmacs);
	free (key);
	if (ferror(stdin)) { perror("stdin"); return 1; }
	return 0;
	l1:	PQclear(result);
		PQfinish(db);
		if (hmacs) free(hmacs);
	l0:	free(key);
		return -1; }

//IN GOD WE TRVST.

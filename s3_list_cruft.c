#define USE "verity_s3_list_cruft 'db conn string' key_file < output_of_s3_list_keys\n"

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

int compar(const void *a, const void *b){ return strcmp(*(char**)a,*(char**)b);}

int main (int argc, char ** argv) {
	PGconn *db;
	PGresult *result;
	unsigned int key_l, n_alloc=0, n_data=0, i;
	char **hmacs=NULL, s3_key[S3_KEY_MAX_LEN+2], *s3_key_p=s3_key;
	unsigned char *hmac_binary, *key;
	if (argc!=3) { fputs(USE,stderr); return 1; }
	if (read_whole_file(argv[2],&key,&key_l)) { perror(argv[2]); return 1; }
	db=PQconnectdb(argv[1]);
	if (PQstatus(db)!=CONNECTION_OK){ SQLERR; AT; goto l0; }
	result=PQexec(db,"begin");
	if (PQresultStatus(result)!=PGRES_COMMAND_OK){ SQLERR; AT; goto l1; }
	result=PQexec(db,"declare hashes cursor for select distinct content from inodes where mode/4096=8");
	if (PQresultStatus(result)!=PGRES_COMMAND_OK){ SQLERR; AT; goto l1; }
	PQclear(result);
	while(1){
		result=PQexec(db,"fetch hashes");
		if (PQresultStatus(result)!=PGRES_TUPLES_OK) { SQLERR; AT; goto l1; }
		if (!PQntuples(result)) break;
		hmac_binary=HMAC(EVP_sha256(),key,key_l,(unsigned char const *)PQgetvalue(result,0,0),2*SHA256_DIGEST_LENGTH,NULL,NULL);
		if	(n_alloc==n_data)
			{	n_alloc=1+3*n_alloc;
				hmacs=realloc(hmacs,n_alloc*sizeof(char *));
				if (!hmacs) { fputs("realloc failed\n",stderr); goto l1; }}
		hmacs[n_data]=malloc(2*SHA256_DIGEST_LENGTH+1);
		if (!hmacs[n_data]) { AT; goto l1; }
		for	(i=0;i<SHA256_DIGEST_LENGTH;i++)
			if	(sprintf(&hmacs[n_data][2*i],"%02hhx",hmac_binary[i])<0)
				{ AT; goto l1; }
		PQclear(result);
		n_data++; }
	PQclear(result);
	PQexec(db,"close hashes");
	if (PQresultStatus(result)!=PGRES_COMMAND_OK){ SQLERR; AT; goto l1; }
	PQclear(result);
	PQfinish(db);
	qsort(hmacs,n_data,sizeof(char *),compar);
	while	(!feof(stdin))
		{	if (!fgets(s3_key,S3_KEY_MAX_LEN+2,stdin)) break;
			i=strlen(s3_key)-1;
			if (s3_key[i]=='\n') s3_key[i]='\0';
			if	(!bsearch(
					&s3_key_p,
					hmacs,
					n_data,
					sizeof(char *),
					compar))
				puts(s3_key); }
	if (ferror(stdin)) { perror("stdin"); goto l0_5; }
	for (i=0;i<n_data;i++) free(hmacs[i]);
	if (hmacs) free(hmacs);
	free (key);
	return 0;
	l1:	PQclear(result);
		PQfinish(db);
	l0_5:	for (i=0;i<n_data;i++) free(hmacs[i]);
		if (hmacs) free(hmacs);
	l0:	free(key);
		return -1; }

//IN GOD WE TRVST.

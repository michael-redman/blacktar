#define USE "paths infile < hashlist\n"

#include <linux/limits.h>
#include <math.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fgetsnull.h>

#include "at.h"

#define HASH_LEN (2*SHA256_DIGEST_LENGTH)

struct lookup_s{
	char hash[HASH_LEN];
	unsigned long long offset; };

int compar (void const *a, void const *b)
{	return memcmp(
		((struct lookup_s *)a)->hash,
		((struct lookup_s *)b)->hash,
		HASH_LEN); }

int main(int argc, char ** argv){
	struct lookup_s * base=NULL, *p;
	unsigned int n_data=0, n_alloc=0, alloc_try;
	unsigned long long offset=0;
	int c;
	FILE * stream;
	char hash[HASH_LEN+2];
	if	(!(stream=fopen(argv[1],"rb")))
		{ perror(argv[1]); return 1; }
	while	(!feof(stream))
		{	if	(n_data==n_alloc)
				{	alloc_try=1+3*n_alloc;
					p=realloc(base,alloc_try*sizeof(struct lookup_s));
					if (!p) { perror("realloc failed " AT); goto l_0_0; }
					base=p;
					n_alloc=alloc_try; }
			if (fread(&base[n_data],HASH_LEN,1,stream)!=1) break;
			base[n_data++].offset=offset;
			offset+=HASH_LEN;
			do	{	c=fgetc(stream);
					if (c==EOF) { fprintf(stderr,"path not read for hash %s " AT, hash); goto l_0_0; }
					offset++;
					if (!c) break; }
				while(!feof(stream)); }
	if (ferror(stream)) { perror(argv[1]); AT_ERR; goto l_0_0; }
	while	(!feof(stdin))
		{	if	(!fgets(hash,HASH_LEN+2,stdin))
				break; 
			hash[HASH_LEN]='\0';
			if	(!(p=bsearch(hash,base,n_data,sizeof(struct lookup_s),compar)))
				{	fprintf(stderr,"path not found for %s\n",hash);
					continue; }
			if	(fseek(stream,p->offset+HASH_LEN,SEEK_SET))
				{ perror(argv[1]); AT_ERR; goto l_0_0; }
			fputs(hash,stdout);
			do	{	c=fgetc(stream);
					if (c==EOF) { fprintf(stderr,"short read of path for hash %s " AT, hash); goto l_0_0; }
					fputc(c,stdout);
					if (!c) break; }
				while(!feof(stdin)); }
	if (base) free(base);
	if (fclose(stream)) { perror(argv[1]); return 1; }
	return 0;
	l_0_0:	if (base) free(base);
		if (fclose(stream)) perror(argv[1]);
		exit(EXIT_FAILURE); }

//IN GOD WE TRVST.

#define USE "hashes file_made_by_hmacs < hmac_list"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char read_record
	(	char * const buf,
		unsigned long const width,
		unsigned long const item,
		FILE * stream)
	{	if (fseek(stream,item*width,SEEK_SET)) return 1;
		if (fread(buf,width,1,stream)!=1) return 1;
		return 0; }

char fbsearch
	(	char const * const key,
		FILE * stream,
		unsigned long const nel,
		unsigned long const width,
		int (*compar)(const void *, const void *),
		long * result)
	{	int r;
		unsigned long low=0, midpoint, high=nel-1;
		char * buf = malloc(width);
		if (!buf) return 1;
		do	{	midpoint=(high+low)/2;
				if	(read_record(buf,width,midpoint,stream))
					goto f0;
				r=compar(key,buf);
				if (!r) { *result=midpoint; goto s0; }
				if	(r<0)
					high=midpoint;
					else low=midpoint+1; }
			while (high-low>0);
		if (read_record(buf,width,low,stream)) goto f0;
		r=compar(key,buf);
		if (!r) { *result=high; goto s0; }
		if	(r>0)
			*result=-high-2;
			else *result=-high-1;
		s0:	free(buf);
			return 0;
		f0:	free(buf);
			return 1; }

int compare_hmacs
	(const void * a, const void * b)
	{	return strncmp(
			(char const * const)a,
			(char const * const)b,
			2*SHA256_DIGEST_LENGTH); }

#define REC_LEN (4*SHA256_DIGEST_LENGTH+2)

int main
	(int argc, char ** argv)
	{	char buf[REC_LEN+1];
		long r;
		unsigned long n;
		FILE * stream=fopen(argv[1],"rb");
		if (!stream) { perror(argv[1]); return 1; }
		if (fseek(stream,0,SEEK_END)) { perror(argv[1]); goto f0; }
		r=ftell(stream);
		if (r==-1) goto f0;
		if	(r%REC_LEN)
			{	fputs("data file size not divisible by record size\n",stderr);
				goto f0; }
		n=r/REC_LEN;
		while	(!feof(stdin))
			{	if (!fgets(buf,2*SHA256_DIGEST_LENGTH+2,stdin)) break;
				if	(fbsearch(buf,stream,n,REC_LEN,compare_hmacs,&r))
					{ perror(argv[1]); goto f0; }
				if	(r<0)
					{	fprintf(stderr,"hmac not found in file: %s",buf);
						goto f0; }
				if	(read_record(buf,REC_LEN,r,stream))
					{ perror(argv[2]); goto f0; }
				buf[REC_LEN]='\0';
				fputs(&buf[2*SHA256_DIGEST_LENGTH+1],stdout); }
		if (ferror(stdin)) { perror("stdin"); goto f0; }
		if (fclose(stream)) { perror(argv[1]); return 1; }
		return 0;
		f0:	if (fclose(stream)) perror(argv[1]);
			return 1; }

//IN GOD WE TRVST.

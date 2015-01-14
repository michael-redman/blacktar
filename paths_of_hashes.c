#define USE "paths_of_hashes [-p /path/prefix] [-t as-of-time_t] [-s] 'db connection string' < hmac_list"

#include <arpa/inet.h>
#include <libpq-fe.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "err.h"

#define	SQL0	"select "\
			"path "\
			"from "\
				"paths "\
				"join inodes on paths.device=inodes.device and paths.inode=inodes.inode and paths.ctime=inodes.ctime "\
			"where "\
				"mode-mode%4096=32768 "\
				"and content=$1 "\
				"and xtime<=$2 "
#define PREFIX_SQL		"and substr(path,1,$3)=$4 "
#define EXCLUDE_STALE_PATHS_SQL	"and not exists (select * from paths as alias where alias.path=paths.path and alias.xtime>paths.xtime) "
#define SQL1		"order by xtime desc limit 1"

int main(int argc, char ** argv){
	char hmac[2*SHA256_DIGEST_LENGTH+2], flag=0, *sql, *params[4];
	PGconn *db;
	PGresult *result;
	uint32_t l;
	uint64_t t=htobe64(time(NULL));
	int	c,
		lengths[4]={0,sizeof(uint64_t),sizeof(uint32_t),0},
		types[4]={0,1,1,0};
	params[3]=NULL; //prefix string - tested later
	while ((c=getopt(argc,argv,"sp:t:"))!=-1){ switch(c){
		case 's': flag=1; break;
		case 'p': params[3]=optarg; break;
		case 't': t=htobe64(strtoll(optarg,NULL,10)); break;
		default: fputs(USE,stderr); exit(EXIT_FAILURE); }}
	if (!(argc-optind)) { fputs(USE,stderr); exit(EXIT_FAILURE); }
	params[1]=(char *)&t;
	db=PQconnectdb(argv[optind]);
	if(PQstatus(db)!=CONNECTION_OK){
		fputs(PQerrorMessage(db),stderr);
		exit(EXIT_FAILURE); }
	if	(params[3])
		{ l=htonl(strlen(params[3])); params[2]=(char *)&l; }
	while(!feof(stdin)){
		if (!(params[0]=fgets(hmac,2*SHA256_DIGEST_LENGTH+2,stdin))) break;
		hmac[2*SHA256_DIGEST_LENGTH]='\0';
		if	(params[3])
			{	if	(flag)
					sql=SQL0 PREFIX_SQL SQL1;
					else sql=SQL0 PREFIX_SQL EXCLUDE_STALE_PATHS_SQL SQL1;
				result=PQexecParams(db,sql,4,NULL,(char const * const *)params,lengths,types,0); }
			else{	if(flag)
					sql=SQL0 SQL1;
					else sql=SQL0 EXCLUDE_STALE_PATHS_SQL SQL1;
				result=PQexecParams(db,sql,2,NULL,(char const * const *)params,lengths,types,0); }
		SQLCHECK(db,result,PGRES_TUPLES_OK,err0);
		if
			(!PQntuples(result)||PQgetisnull(result,0,0))
			fprintf(stderr,"path not found for %s\n",hmac);
			else printf("%s%s%c",hmac,PQgetvalue(result,0,0),'\0');
		PQclear(result); }
	PQfinish(db);
	return 0;
	err0:	PQclear(result);
		PQfinish(db);
		exit(EXIT_FAILURE); }

/*IN GOD WE TRVST.*/

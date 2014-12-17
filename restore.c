//Copyright 2014 Michael Redman
//IN GOD WE TRVST.

#define USE "blacktar_restore [-p /path/prefix] [-t as-of-time_t] 'db connection string' /path/to/passphrase/file s3_bucket_name /target/root\n"

/* Logic:

1: Query the database for all the paths we need to restore, along with their modes and other info.
2: For each path:
	2.1: If it's a regular file, put its hmac in a list.  We will sort the list when we're done so we only retrieve each file from the backup store once.
	2.2: If it's a directory, put it in a list of directories.  We set directory permissions and create empties last because we might need to restore a file into a dir that needs to not be writeable
	2.3: If it's a symlink, restore it.
3: Sort & unique the list of hmacs
4: For each unique hmac:
	4.1: Query all the inodes where that content currently lives.
	4.2: For each inode:
		4.2.1: Query all the paths pointing to it
		4.2.2: Restore the file to the first path and set permissions
		4.2.3: For each additional path, link to the first one.
5: For each dir, make sure it exists and has correct permissions */

#define _GNU_SOURCE

#include <errno.h>
#include <libgen.h>
#include <libpq-fe.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include <fgetsnull.h>

#include "err.h"

extern int read_whole_file (char const * const path, unsigned char **buf, unsigned int *data_size);

int mkdir_recursive
(char * const path)
{	char * p=path;
	struct stat st;
	while(1){
		p = strchr(p,'/');
		if (!p) break;
		*p='\0';
		mkdir(path,S_IRWXU);
		*p='/';
		p++; }
	mkdir(path,S_IRWXU);
	if	(lstat(path,&st) || !S_ISDIR(st.st_mode))
		{	fprintf(stderr,"failed creating directory: %s\n",path);
			AT;
			return 1; }
	return 0; }

int set_perms
(char const * const path, const mode_t mode, const uid_t uid, const gid_t gid, const time_t mtime)
{	int r=0;
	struct utimbuf ut;
	if	(getuid())
		{ if (chown(path,-1,gid)) { fputs("error changing group: ",stderr); perror(path); AT; r=1; } }
		else if (chown(path,uid,gid)) { fputs("error setting owner/group: ",stderr); perror(path); AT; r=1; }
	if (chmod(path,mode)) { fputs("error setting mode: ",stderr); perror(path); AT; r=1; }
	ut.actime=mtime;
	ut.modtime=mtime;
	if (utime(path,&ut)) { fputs("error setting mtime: ",stderr); perror(path); AT; r=1; }
	return r; }
		
#define PREFIX_SQL " and substr(paths.path,1,%u)='%s'"

#define ASPRINTF_CHECK(sym) \
if	(r==-1)\
	{	fputs("asprintf failed\n",stderr); AT;\
		goto sym; }

#define CLOSE_LINKS_CURSOR \
PQclear(result1); \
result1=PQexec(db,"close links_cursor"); \
SQLCHECK(db,result1,PGRES_COMMAND_OK,err1); \
PQclear(result1);

int main(int argc, char ** argv){

	int c, r, pipe_fd[2], pid;
	unsigned int l, key_len;
	char	*prefix=NULL, *prefix_escaped=NULL, *sql, *target_root,
		path_ar0[PATH_MAX+1], path_ar1[PATH_MAX+1],
		hmac[2*SHA_DIGEST_LENGTH+2], return_value=0;
	unsigned char * key;
	PGresult * result0, * result1, * result2;
	FILE * hmacs_tmpfile, *dirs_tmpfile, *child_stdout;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	time_t mtime, t=time(NULL);
	while ((c=getopt(argc,argv,"ip:t:"))!=-1){ switch(c){
		case 'p': prefix=optarg; break;
		case 't': t=strtoll(optarg,NULL,10); break;
		default: fputs(USE,stderr); exit(EXIT_FAILURE); }}
	if (argc-optind!=4) { fputs(USE,stderr); exit(EXIT_FAILURE); }
	target_root=argv[optind+3];
	r=strlen(target_root)-1;
	if	(r<0)
		target_root=".";
		else if(target_root[r]=='/') target_root[r]='\0';
	if	(read_whole_file(argv[optind+1],&key,&key_len))
		{ perror(argv[optind+1]); AT; exit(EXIT_FAILURE); }	
	PGconn * db=PQconnectdb(argv[optind]);
	if(PQstatus(db)!=CONNECTION_OK){
		fputs(PQerrorMessage(db),stderr);
		exit(EXIT_FAILURE); }
	if	(	!(hmacs_tmpfile = tmpfile())
			|| !(dirs_tmpfile = tmpfile()))
		{	fputs("error creating tmpfiles\n",stderr); goto err0; }
	result0=PQexec(db,"begin");
	SQLCHECK(db,result0,PGRES_COMMAND_OK,err0);
	PQclear(result0);

#define PATHS_DECLARE "declare paths_cursor cursor for select paths.path "
#ifndef CORRELATED_SUBQUERY
#define PATHS_J0	\
",mode,uid,gid,mtime,content "\
"from "\
	"paths "\
	"join "\
		"(select "\
			"path, max(xtime) as max_xtime "\
			"from paths "\
			"where "\
				"xtime<=%ld"
				//possible PREFIX_SQL
#define PATHS_J1 \
			" group by path) "\
			"as max_xtimes "\
			"on max_xtimes.path=paths.path and max_xtimes.max_xtime=paths.xtime "\
	"join inodes on inodes.device=paths.device and inodes.inode=paths.inode and inodes.ctime=paths.ctime "\
"where "\
	"paths.device is not null"
	//possible PREFIX_SQL
#else
#define PATHS_SQ0 \
",(select mode from inodes where inodes.device=paths.device and inodes.inode=paths.inode and inodes.ctime=paths.ctime) as mode, "\
"(select uid from inodes where inodes.device=paths.device and inodes.inode=paths.inode and inodes.ctime=paths.ctime) as uid, "\
"(select gid from inodes where inodes.device=paths.device and inodes.inode=paths.inode and inodes.ctime=paths.ctime) as gid, "\
"(select mtime from inodes where inodes.device=paths.device and inodes.inode=paths.inode and inodes.ctime=paths.ctime) as mtime, "\
"(select content from inodes where inodes.device=paths.device and inodes.inode=paths.inode and inodes.ctime=paths.ctime) as content "\
" from paths where device is not null and not exists (select * from paths as alias where alias.path=paths.path and alias.xtime>paths.xtime and alias.xtime<=%ld)"
//possible PREFIX_SQL
#endif

	if	(prefix)
		{	l=strlen(prefix);
			//PQExecParams does not work with cursor under PG 7.4 - throws error - so use escape strings instead - see http://www.postgresql.org/message-id/20050117165837.GA80669@winnie.fuhr.org
			if	(!(prefix_escaped=malloc(2*l+1)))
				{ fputs("malloc failed\n",stderr); goto err0; }
			PQescapeStringConn(db,prefix_escaped,prefix,l,NULL);
			#ifndef CORRELATED_SUBQUERY
			int r = asprintf(&sql,PATHS_DECLARE PATHS_J0 PREFIX_SQL PATHS_J1 PREFIX_SQL,t,l,prefix_escaped,l,prefix_escaped);
			#else
			int r = asprintf(&sql,PATHS_DECLARE PATHS_SQ0 PREFIX_SQL,t,l,prefix_escaped);
			#endif
			ASPRINTF_CHECK(err0) }
		else{
			#ifndef CORRELATED_SUBQUERY
			r=asprintf(&sql,PATHS_DECLARE PATHS_J0 PATHS_J1,t);
			#else
			r=asprintf(&sql,PATHS_DECLARE PATHS_SQ0,t);
			#endif
			ASPRINTF_CHECK(err0) }
	result0=PQexec(db,sql);
	free(sql);
	SQLCHECK(db,result0,PGRES_COMMAND_OK,err0);
	PQclear(result0);
	while(1){
		result0=PQexec(db,"fetch paths_cursor");
		SQLCHECK(db,result0,PGRES_TUPLES_OK,err0);
		if(!PQntuples(result0)) break;
		if	(	PQgetisnull(result0,0,0)
				|| PQgetisnull(result0,0,1)
				|| PQgetisnull(result0,0,2)
				|| PQgetisnull(result0,0,3)
				|| PQgetisnull(result0,0,4))
			{	fputs("sanity check failed\n",stderr); AT;
				goto err1; }
		mode_t mode=strtol(PQgetvalue(result0,0,1),NULL,10);
		switch	(mode-mode%4096){
			case 16384: //dir
				mode=strtol(PQgetvalue(result0,0,1),NULL,10);
				uid=strtol(PQgetvalue(result0,0,2),NULL,10);
				gid=strtol(PQgetvalue(result0,0,3),NULL,10);
				mtime=strtoll(PQgetvalue(result0,0,4),NULL,10);
				if	(	fputs(PQgetvalue(result0,0,0),dirs_tmpfile)==EOF
						|| fputc(0,dirs_tmpfile)
						|| fwrite(&mode,sizeof(mode_t),1,dirs_tmpfile)!=1
						|| fwrite(&uid,sizeof(uid_t),1,dirs_tmpfile)!=1
						|| fwrite(&gid,sizeof(gid_t),1,dirs_tmpfile)!=1
						|| fwrite(&mtime,sizeof(time_t),1,dirs_tmpfile)!=1)
					{	fputs("error writing to dirs tmpfile\n",stderr); goto err1; }
				break;
			case 32768: //regular file
				if	(PQgetisnull(result0,0,5))
					{	fputs("sanity check failed\n",stderr); AT;
						goto err1; }
				fprintf(	
					hmacs_tmpfile,
					"%s\n",
					PQgetvalue(result0,0,5));
				break;
			case 40960: //symlink
				if	(PQgetisnull(result0,0,5))
					{	fputs("sanity check failed\n",stderr); AT;
						goto err1; }
				if	(PQgetvalue(result0,0,0)[0]=='/')
					sprintf(path_ar0,"%s%s",target_root,PQgetvalue(result0,0,0));
					else sprintf(path_ar0,"%s/%s",target_root,PQgetvalue(result0,0,0));
				strcpy(path_ar1,path_ar0);
				mkdir_recursive(dirname(path_ar1));
				if	(symlink(PQgetvalue(result0,0,5),path_ar0))
					{	fputs("could not create symlink\n",stderr);
						perror(path_ar0); AT;
						goto err1; }
				break;
			default:
				fputs("sanity check failed\n",stderr); AT;
				goto err1; }
		PQclear(result0); }
	PQclear(result0);
	result0=PQexec(db,"close paths_cursor");
	SQLCHECK(db,result0,PGRES_COMMAND_OK,err0);
	PQclear(result0);

	if	(fseek(hmacs_tmpfile,0,SEEK_SET))
		{ perror("seek on hmacs tmpfile failed\n"); AT; goto err0;}
	if	(pipe(pipe_fd))
		{ perror("pipe failed"); AT; goto err0; }
	if	(!(pid=fork()))
		{	if	(	dup2(fileno(hmacs_tmpfile),STDIN_FILENO)==-1
					||dup2(pipe_fd[1],STDOUT_FILENO)==-1
					||close(pipe_fd[0]))
				{	perror("i/o redirection failed"); AT;
					exit(EXIT_FAILURE); }
			execl("/usr/bin/sort","/usr/bin/sort","-u",NULL);
			perror("execl failed"); AT; exit(EXIT_FAILURE); }
	if	(pid==-1)
		{ perror("fork failed"); AT; goto err0; }
	wait(&r);
	if	(	!WIFEXITED(r) || WEXITSTATUS(r)
			|| close(pipe_fd[1])
			|| !(child_stdout=fdopen(pipe_fd[0],"rb")))
		{ perror("sort child error"); AT; goto err0; }

	while	(!feof(child_stdout))
		{	if(!fgets(hmac,2*SHA_DIGEST_LENGTH+2,child_stdout)) break;
			hmac[2*SHA_DIGEST_LENGTH]='\0';

#define INODES_SQL "declare inode_cursor cursor for select "\
	"device,inode,ctime "\
	"from inodes "\
	"where "\
		"mode-mode%%4096=32768 "\
		"and content='%s' "\
		"and exists (select * from paths where paths.device=inodes.device and paths.inode=inodes.inode and paths.ctime=inodes.ctime and xtime=(select max(xtime) from paths as alias where alias.path=paths.path and xtime<=%ld)"

			if	(prefix)
				r = asprintf(&sql,INODES_SQL PREFIX_SQL ")",hmac,t,l,prefix_escaped);
				else r = asprintf(&sql,INODES_SQL ")",hmac,t);
			ASPRINTF_CHECK(err0)
			result0=PQexec(db,sql);
			free(sql);
			SQLCHECK(db,result0,PGRES_COMMAND_OK,err0);
			PQclear(result0);
			while(1){
				result0=PQexec(db,"fetch inode_cursor");
				SQLCHECK(db,result0,PGRES_TUPLES_OK,err0);
				if(!PQntuples(result0)) break;

#define LINKS_SQ0 \
"declare links_cursor cursor for select"\
	" path"\
	" from paths"\
	" where"\
		" device=%s and inode=%s and ctime=%s"\
		" and xtime=(select max(xtime) from paths as alias where alias.path=paths.path and xtime<=%ld)"
		//possible PREFIX_SQL

				if	(prefix)
					r=asprintf(&sql,LINKS_SQ0 PREFIX_SQL,PQgetvalue(result0,0,0),PQgetvalue(result0,0,1),PQgetvalue(result0,0,2),t,l,prefix_escaped);
					else r=asprintf(&sql,LINKS_SQ0,PQgetvalue(result0,0,0),PQgetvalue(result0,0,1),PQgetvalue(result0,0,2),t);

				ASPRINTF_CHECK(err1)
				result1 = PQexec(db,sql);
				free(sql);
				SQLCHECK(db,result1,PGRES_COMMAND_OK,err1);
				PQclear(result1);
				path_ar0[0]=0;
				while(1){
					result1=PQexec(db,"fetch links_cursor");
					SQLCHECK(db,result1,PGRES_TUPLES_OK,err1);
					if(!PQntuples(result1)) break;
					if	(!path_ar0[0])
						{	sprintf(path_ar0,"%s/%s",target_root,PQgetvalue(result1,0,0));
							if	(pipe(pipe_fd))
								{ perror("pipe failed"); AT; goto err2; }
							if	(!(pid=fork()))
								{	if	(	dup2(pipe_fd[0],STDIN_FILENO)==-1
											||close(pipe_fd[0])
											||close(pipe_fd[1]))
									{	perror("i/o redirection failed"); AT;
										exit(EXIT_FAILURE); }
									execl("/usr/local/share/blacktar/retrieve","/usr/local/share/blacktar/retrieve",argv[optind+2],hmac,path_ar0,NULL);
									perror("execl failed"); AT; exit(EXIT_FAILURE); }
							if	(	close(pipe_fd[0])
									|| pid==-1
									|| write(pipe_fd[1],key,key_len)!=key_len
									|| close(pipe_fd[1]))
								{	perror("failed invoking retrieve command"); AT; wait(&r); goto err2; }
							wait(&r);
							if	(WIFEXITED(r)&&WEXITSTATUS(r)==3)
								{	fprintf(stderr,"ERROR: HMAC NOT FOUND: %s (%s), continuing\n",hmac,PQgetvalue(result1,0,0)); AT;
									return_value=3;
									CLOSE_LINKS_CURSOR
									goto hmac_done_cleanup; }
							if (!WIFEXITED(r)||WEXITSTATUS(r)) { fprintf(stderr,"retrieve child returned %d\n",WEXITSTATUS(r)); AT; goto err2; }
							r=asprintf(&sql,"select mode,uid,gid,mtime from inodes where device=%s and inode=%s and ctime=%s",PQgetvalue(result0,0,0),PQgetvalue(result0,0,1),PQgetvalue(result0,0,2));
							ASPRINTF_CHECK(err2)
							result2=PQexec(db,sql);
							free(sql);
							SQLCHECK(db,result2,PGRES_TUPLES_OK,err2);
							if	(set_perms(
									path_ar0,
									strtol(PQgetvalue(result2,0,0),NULL,10),
									strtol(PQgetvalue(result2,0,1),NULL,10),
									strtol(PQgetvalue(result2,0,2),NULL,10),
									strtoll(PQgetvalue(result2,0,3),NULL,10)))
								AT;
							PQclear(result2); }
						 else{	sprintf(path_ar1,"%s/%s",target_root,PQgetvalue(result1,0,0));
							 if	(link(path_ar0,path_ar1))
								{ perror(path_ar1); AT; goto err2; }}
					PQclear(result1); }
				CLOSE_LINKS_CURSOR
				PQclear(result0); }
			hmac_done_cleanup:
			PQclear(result0);
			result0=PQexec(db,"close inode_cursor");
			SQLCHECK(db,result0,PGRES_COMMAND_OK,err0);
			PQclear(result0);
			}
	if	(fclose(child_stdout)||fclose(hmacs_tmpfile))
		{ perror("error closing files: "); perror(NULL); AT; goto err0; }

	result0=PQexec(db,"end");
	SQLCHECK(db,result0,PGRES_COMMAND_OK,err0);
	PQclear(result0);
	if (prefix_escaped) free(prefix_escaped);
	PQfinish(db);
	free(key);

	if	(fseek(dirs_tmpfile,0,SEEK_SET))
		{ perror("seek on dirs tmpfile failed\n"); AT; exit(EXIT_FAILURE); }
	while	(!feof(dirs_tmpfile))
		{	if (!fgetsnull(path_ar0,PATH_MAX+1,dirs_tmpfile)) break;
			sprintf(path_ar1,"%s/%s",target_root,path_ar0);
			if	(mkdir_recursive(path_ar1))
				{	fputs("recursive directory create failed\n",stderr);
					perror(path_ar1);
					exit(EXIT_FAILURE); }
			if	(	fread(&mode,sizeof(mode_t),1,dirs_tmpfile)!=1
					|| fread(&uid,sizeof(uid_t),1,dirs_tmpfile)!=1
					|| fread(&gid,sizeof(gid_t),1,dirs_tmpfile)!=1
					|| fread(&mtime,sizeof(time_t),1,dirs_tmpfile)!=1)
				{	fprintf(stderr,"failed reading mode/owner/mtime info from dirs tmpfile: %s\n",path_ar0);
					perror(NULL);
					exit(EXIT_FAILURE); }
			if (set_perms(path_ar1,mode,uid,gid,mtime)) AT; }
	if	(fclose(dirs_tmpfile))
		{	fputs("error closing dirs tmpfile\n",stderr); AT;
			perror(NULL);
			exit(EXIT_FAILURE); }

	exit(return_value);
	err2:	PQclear(result1);
	err1:	PQclear(result0);
	err0:	if (prefix_escaped) free(prefix_escaped);
		PQfinish(db);
		free(key);
		exit(EXIT_FAILURE); }

/*IN GOD WE TRVST.*/

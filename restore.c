#define USE "verity_list ... | grep -z ... | blacktar_restore [ -r /restore/root ] [-t as-of-time_t] 'db connection string' /path/to/passphrase/file s3_bucket_name\n"

/* Logic:


First read from stdin in a loop all the paths to restore.

For each path, query the database for its mode to tell what it is.

If it's a regular file, put its hash in a list and its path in a temprary table.  The list of hashes is so we only fetch each object from the backup store once, and the temporary table is for querying which of the paths pointing to an inode are in the set of paths to restore.

If it's a directory, put it in a list of directories.  We set directory permissions and create empties last because we might need to restore a file into a dir that needs to not be writeable

If it's a symlink, restore it (including any parent directories).


Second, restore the content.

Sort & unique the list of hmacs

For each hmac, query all the inodes that currently have that content.

For each inode, query all the paths pointing to it that are in the set to restore.

For the first path in the loop, get the content from the backup store and restore it to that path.

For for each remaining path, hardlink to the source.  If hardlinking fails (e.g. paths that were on the same device during backup are not during restore) print an error and exit so the user can figure out what to do (e.g. restore the paths in subsets) - not clear whether the better behavior would be to restore a copy or a symlink.


Third, loop thru the table of directories, making any that do not yet exist and setting permissions on all. */


#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <libpq-fe.h>
#include <linux/limits.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include <hexbytes.h>

#include "err.h"

extern int read_whole_file (char const * const path, unsigned char **buf, unsigned int *data_size);

char * restore_root=".";
unsigned int restore_root_len=1;

char build_restore_path
(char const * const path, char * const outbuf)
{	char const *p=path;
	while (*p=='/') p++;
	if	(snprintf(outbuf,PATH_MAX+1,"%s/%s",restore_root,p)>=PATH_MAX+1)
		{	fprintf(stderr,"path truncated: %s/%s\n",restore_root,p);
			return 1; }
	return 0; }

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
		{	if (chown(path,-1,gid))
			{	fputs("error changing group: ",stderr);
				perror(path); AT; r=1; } }
		else if	(chown(path,uid,gid))
			 {	fputs("error setting owner/group: ",stderr);
				perror(path); AT; r=1; }
	if	(chmod(path,mode))
		{ fputs("error setting mode: ",stderr); perror(path); AT; r=1; }
	ut.actime=mtime;
	ut.modtime=mtime;
	if	(utime(path,&ut))
		{fputs("error setting mtime: ",stderr); perror(path); AT; r=1;}
	return r; }

#define CLOSE_LINKS_CURSOR \
PQclear(result1); \
result1=PQexec(db,"close links_cursor"); \
SQLCHECK(db,result1,PGRES_COMMAND_OK,err1); \
PQclear(result1);
		
int main
(int argc, char ** argv)
{	int r, pipe_fd[2], pid;
	unsigned int key_len;
	char	path_ar0[PATH_MAX+1], path_ar1[PATH_MAX+1],
		hmac_text[2*SHA256_DIGEST_LENGTH+1],
		hash[2*SHA256_DIGEST_LENGTH+1], return_value=0, *buf=NULL;
	size_t buf_len=0;
	unsigned char * key, *hmac_binary;
	PGresult * result0, * result1;
	FILE * hashes_tmpfile, *dirs_tmpfile, *child_stdout;
	mode_t mode;
	uid_t uid; gid_t gid;
	uint64_t mtime, t=htobe64(time(NULL));
	while	((r=getopt(argc,argv,"r:t:"))!=-1){ switch(r){
		case 'r':
			restore_root=optarg;
			restore_root_len=strlen(restore_root);
			while	(restore_root[restore_root_len-1]=='/')
				restore_root[--restore_root_len]='\0';
			break;
		case 't': t=htobe64(strtoll(optarg,NULL,10)); break;
		default: fputs(USE,stderr); exit(EXIT_FAILURE); }}
	if (argc-optind!=3) { fputs(USE,stderr); exit(EXIT_FAILURE); }
	if	(read_whole_file(argv[optind+1],&key,&key_len))
		{ perror(argv[optind+1]); AT; exit(EXIT_FAILURE); }	
	PGconn * db=PQconnectdb(argv[optind]);
	if(PQstatus(db)!=CONNECTION_OK){
		fputs(PQerrorMessage(db),stderr);
		free(key);
		exit(EXIT_FAILURE); }
	if	(	!(hashes_tmpfile = tmpfile())
			|| !(dirs_tmpfile = tmpfile()))
		{	fputs("error creating tmpfiles\n",stderr); goto err0; }
	result0=PQexec(db,"begin");
	SQLCHECK(db,result0,PGRES_COMMAND_OK,err1);
	PQclear(result0);
	result0=PQexec(db,"create temporary table paths_to_restore(path text not null unique)");
	SQLCHECK(db,result0,PGRES_COMMAND_OK,err1);
	PQclear(result0);

	//Part 1
	while	(!feof(stdin))
		{	if (getdelim(&buf,&buf_len,'\0',stdin)==-1) break;
			result0=PQexecParams(db,
				"select "\
					"mode, uid, gid, mtime, content "\
					"from inodes join paths on paths.device=inodes.device and paths.inode=inodes.inode and paths.ctime=inodes.ctime "\
					"where path=$1 and not exists (select * from paths as alias where alias.path=paths.path and alias.xtime>paths.xtime and alias.xtime<$2)",
				2,NULL,
				(char const * const []){
					buf,
					(char const * const)&t },
				(int const []){0, sizeof(uint64_t) },
				(int const []){0,1},1);
			SQLCHECK(db,result0,PGRES_TUPLES_OK,err1);
			if	(!PQntuples(result0))
				{	fprintf(stderr, "error in stdin read loop: no current record found for path %s\n",buf);
					PQclear(result0);
					continue; }
			if	(	PQgetisnull(result0,0,0)
					|| PQgetisnull(result0,0,1)
					|| PQgetisnull(result0,0,2)
					|| PQgetisnull(result0,0,3))
				{	fputs("sanity check failed\n",stderr); AT;
					goto err1; }
			mode=ntohl(*(uint32_t *)PQgetvalue(result0,0,0));
			switch	(mode-mode%4096){
				case 16384: //dir
					uid=ntohl(*(uint32_t *)PQgetvalue(result0,0,1));
					gid=ntohl(*(uint32_t *)PQgetvalue(result0,0,2));
					mtime=be64toh(*(uint64_t *)PQgetvalue(result0,0,3));
					if	(	fputs(buf,dirs_tmpfile)==EOF
							|| fputc(0,dirs_tmpfile)
							|| fwrite(&mode,sizeof(mode_t),1,dirs_tmpfile)!=1
							|| fwrite(&uid,sizeof(uid_t),1,dirs_tmpfile)!=1
							|| fwrite(&gid,sizeof(gid_t),1,dirs_tmpfile)!=1
							|| fwrite(&mtime,sizeof(time_t),1,dirs_tmpfile)!=1)
						{	fputs("error writing to dirs tmpfile\n",stderr); goto err1; }
					break;
				case 32768: //regular file
					if	(PQgetisnull(result0,0,4))
						{	fputs("sanity check failed\n",stderr); AT;
							goto err1; }
					fprintf(	
						hashes_tmpfile,
						"%s\n",
						PQgetvalue(result0,0,4));
					result1=PQexecParams(db,
						"insert into paths_to_restore values($1)",1,
						NULL, (char const * const []){ buf },
						(int const []){ 0 }, (int const []){0},0);
						SQLCHECK(db,result1,PGRES_COMMAND_OK,err2);
						PQclear(result1);
					break;
				case 40960: //symlink
					if	(PQgetisnull(result0,0,4))
						{	fputs("sanity check failed\n",stderr); AT;
							goto err1; }
					if	(build_restore_path(buf,path_ar1))
						{	fputs("build restore path failed\n",stderr); AT;
							goto err1; }
					strcpy(path_ar0,path_ar1);
					//dirname modifies arg
					mkdir_recursive(dirname(path_ar1));
					if	(symlink(PQgetvalue(result0,0,4),path_ar0))
						{	fputs("could not create symlink\n",stderr);
							perror(path_ar0); AT;
							goto err1; }
					break;
				default:
					fputs("sanity check failed\n",stderr); AT;
					goto err1; }
			PQclear(result0); }
	if (ferror(stdin)) { perror("stdin"); goto err0; }

	//Part 2
	if	(fseek(hashes_tmpfile,0,SEEK_SET))
		{ perror("seek on hashes tmpfile failed\n"); AT; goto err0;}
	if	(pipe(pipe_fd))
		{ perror("pipe failed"); AT; goto err0; }
	if	(!(pid=fork()))
		{	if	(	dup2(fileno(hashes_tmpfile),STDIN_FILENO)==-1
					||dup2(pipe_fd[1],STDOUT_FILENO)==-1
					||close(pipe_fd[0]))
				{	perror("i/o redirection failed"); AT;
					exit(EXIT_FAILURE); }
			execl("/usr/bin/sort","/usr/bin/sort","-u",NULL);
			perror("execl failed"); AT; exit(EXIT_FAILURE); }
	if	(pid==-1)
		{ perror("fork failed"); AT; goto err0; }
	while	(wait(&r)!=-1)
		if	(!WIFEXITED(r) || WEXITSTATUS(r))
			{ perror("sort child error"); AT; goto err0; }
	if	(close(pipe_fd[1]) || !(child_stdout=fdopen(pipe_fd[0],"rb")))
		{ perror("sort child error"); AT; goto err0; }

	while	(!feof(child_stdout))
		{	if(!fgets(hash,2*SHA256_DIGEST_LENGTH+2,child_stdout)) break;
			hash[2*SHA256_DIGEST_LENGTH]='\0';
			result0=PQexecParams(db,
				"declare inode_cursor cursor for select "\
					"device,inode,ctime,mode,uid,gid,mtime "\
					"from inodes "\
					"where "\
						"mode-mode%4096=32768 "\
						"and content=$1 "\
						"and exists (select * from paths where paths.device=inodes.device and paths.inode=inodes.inode and paths.ctime=inodes.ctime and xtime=(select max(xtime) from paths as alias where alias.path=paths.path and xtime<=$2))",
				2,NULL,
				(char const * const []){
					hash,
					(char const * const)&t },
				(int const []){0, sizeof(uint64_t) },
				(int const []){0,1},
				0); //got text back for device, inode, ctime even when specifying 1 for binary results
			SQLCHECK(db,result0,PGRES_COMMAND_OK,err1);
			PQclear(result0);
			while(1){
				result0=PQexec(db,"fetch inode_cursor");
				SQLCHECK(db,result0,PGRES_TUPLES_OK,err0);
				if(!PQntuples(result0)) break;
				result1=PQexecParams(db,
					"declare links_cursor cursor for select path from paths where "\
						"device=$1 and inode=$2 and ctime=$3 "\
						"and xtime=(select max(xtime) from paths as alias where alias.path=paths.path and xtime<=$4) "\
						"and exists (select * from paths_to_restore where paths_to_restore.path=paths.path)",
					4,NULL,
					(char const * const []){
						PQgetvalue(result0,0,0),
						PQgetvalue(result0,0,1),
						PQgetvalue(result0,0,2),
						(char const * const)&t},
					(int const []){0,0,0,sizeof(uint64_t)},
					(int const []){0,0,0,1},0);
				SQLCHECK(db,result1,PGRES_COMMAND_OK,err2);
				PQclear(result1);
				path_ar0[0]=0;
				while(1){
					result1=PQexec(db,"fetch links_cursor");
					SQLCHECK(db,result1,PGRES_TUPLES_OK,err2);
					if(!PQntuples(result1)) break;
					if	(!path_ar0[0])
						{	if	(build_restore_path(PQgetvalue(result1,0,0),path_ar0))
								{	fputs("build restore path failed\n",stderr); AT;
									goto err2; }
							hmac_binary=HMAC(EVP_sha256(),key,key_len,(unsigned char const *)hash,2*SHA256_DIGEST_LENGTH,NULL,NULL);
							hexbytes_print(hmac_binary,SHA256_DIGEST_LENGTH,hmac_text);
							if	(pipe(pipe_fd))
								{ perror("pipe failed"); AT; goto err2; }
							if	(!(pid=fork()))
								{	if	(	dup2(pipe_fd[0],STDIN_FILENO)==-1
											||close(pipe_fd[0])
											||close(pipe_fd[1]))
									{	perror("i/o redirection failed"); AT;
										exit(EXIT_FAILURE); }
									execl("/usr/local/share/blacktar/retrieve","/usr/local/share/blacktar/retrieve",argv[optind+2],hmac_text,path_ar0,hash,NULL);
									perror("execl failed"); AT; exit(EXIT_FAILURE); }
							if	(	close(pipe_fd[0])
									|| pid==-1
									|| write(pipe_fd[1],key,key_len)!=key_len
									|| close(pipe_fd[1]))
								{	perror("failed invoking retrieve command"); AT; while(wait(&r)==-1); goto err2; }
							while	(wait(&r)!=-1)
								{	if	(WIFEXITED(r)&&WEXITSTATUS(r)==3)
										{	fprintf(stderr,"ERROR: FILE NOT FOUND FOR HASH: %s (%s), continuing\n",hash,PQgetvalue(result1,0,0)); AT;
											return_value=3;
											CLOSE_LINKS_CURSOR
											goto hash_done_cleanup; }
									if (!WIFEXITED(r)||WEXITSTATUS(r)) { fprintf(stderr,"retrieve child returned %d\n",WEXITSTATUS(r)); AT; goto err2; } }
							if	(set_perms(
									path_ar0,
									strtol(PQgetvalue(result0,0,3),NULL,10),
									strtol(PQgetvalue(result0,0,4),NULL,10),
									strtol(PQgetvalue(result0,0,5),NULL,10),
									strtoll(PQgetvalue(result0,0,6),NULL,10)))
								AT; }
						 else{	if	(build_restore_path(PQgetvalue(result1,0,0),path_ar1))
								{	fputs("build restore path failed\n",stderr); AT;
									goto err2; }
							if	(link(path_ar0,path_ar1))
								{ perror(path_ar1); AT; goto err2; }}
					PQclear(result1); }
				CLOSE_LINKS_CURSOR
				PQclear(result0); }
			hash_done_cleanup:
				PQclear(result0);
				result0=PQexec(db,"close inode_cursor");
				SQLCHECK(db,result0,PGRES_COMMAND_OK,err0);
				PQclear(result0); }
	if	(fclose(child_stdout)||fclose(hashes_tmpfile))
		{ perror("error closing files: "); perror(NULL); AT; goto err0; }
	PQfinish(db);
	free(key);

	//Part 3
	if	(fseek(dirs_tmpfile,0,SEEK_SET))
		{	perror("seek on dirs tmpfile failed\n");
			AT; exit(EXIT_FAILURE); }
	while	(!feof(dirs_tmpfile))
		{	if (getdelim(&buf,&buf_len,'\0',dirs_tmpfile)==-1) break;
			if	(build_restore_path(buf,path_ar0))
				{	fputs("build_restore_path failed\n",stderr);
					AT; goto label0; }
			if	(mkdir_recursive(path_ar0))
				{	fputs("recursive directory create failed\n",stderr);
					perror(path_ar0);
					goto label0; }
			if	(	fread(&mode,sizeof(mode_t),1,dirs_tmpfile)!=1
					|| fread(&uid,sizeof(uid_t),1,dirs_tmpfile)!=1
					|| fread(&gid,sizeof(gid_t),1,dirs_tmpfile)!=1
					|| fread(&mtime,sizeof(time_t),1,dirs_tmpfile)!=1)
				{	fprintf(stderr,"failed reading mode/owner/mtime info from dirs tmpfile for file: %s\n",path_ar0);
					perror(NULL);
					goto label0; }
			if (set_perms(path_ar0,mode,uid,gid,mtime)) AT; }
	if (ferror(stdin)) { perror("stdin"); AT; goto label0; }
	free(buf);
	if	(fclose(dirs_tmpfile))
		{	fputs("error closing dirs tmpfile\n",stderr); AT;
			perror(NULL);
			exit(EXIT_FAILURE); }
	exit(return_value);
	label0:	free(buf);
		return 1;
	err2:	PQclear(result1);
	err1:	PQclear(result0);
	err0:	PQfinish(db);
		free(key);
		free(buf);
		exit(EXIT_FAILURE); }
	
/*IN GOD WE TRVST.*/

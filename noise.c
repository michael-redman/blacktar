#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

int main(int argc, char ** argv){
	struct stat stat_s;
	unsigned int n,i;
	srandom(time(NULL));
	unsigned char x;
	FILE *stream;
	if (stat(argv[1],&stat_s)) { perror(argv[1]); exit(EXIT_FAILURE); }
	if(!(stream=fopen(argv[2],"wb"))){perror(argv[2]); exit(EXIT_FAILURE); }
	n=
		(stat_s.st_size>=128?0:128-stat_s.st_size)
		+ .01*stat_s.st_size*random()/RAND_MAX;
	for
		(i=0;i<n;i++)
		{
			x=random();
			if
				(fwrite(&x,sizeof(unsigned char),1,stream)!=1)
				{ perror(argv[2]); exit(EXIT_FAILURE); }}
	if(fclose(stream)){ perror(argv[2]); exit(EXIT_FAILURE); }
	exit(EXIT_SUCCESS); }

/*IN GOD WE TRVST.*/

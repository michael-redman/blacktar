#include <stdio.h>
#include <stdlib.h>

#include "err.h"

int read_whole_file
	(char const * const path, unsigned char **buf, unsigned int *data_size)
	{
		FILE * stream;
		unsigned int alloc_size=0, bytes_read, goal;
		*buf=NULL;
		*data_size=0;
		if (!(stream=fopen(path,"rb"))){ perror(path); AT; return -1; }
		while (!feof(stream)) {
			if (alloc_size==*data_size) {
				alloc_size=1+3*alloc_size;
				if	(!(*buf=realloc(*buf,alloc_size)))
					{ fputs("alloc failed\n",stderr); AT; goto out1; }}
			goal=alloc_size-*data_size;
			if	((bytes_read=fread(&(*buf)[*data_size],1,goal,stream))!=goal)
				if (ferror(stream)) {perror(path); AT; goto out1;}
			*data_size+=bytes_read; }
		if (fclose(stream)) { perror(path); AT; goto out0; }
		return 0;
		out1:	if (fclose(stream)) { perror(path); AT; }
		out0:	if (*buf) free(*buf);
			return -1;}

/*IN GOD WE TRVST.*/

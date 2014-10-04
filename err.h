#ifndef _ERR_H
#define _ERR_H

#define AT do{ fprintf(stderr,"at "__FILE__": %u\n",__LINE__); }while(0)

#define SQLCHECK(db,result,expected,label) do{ if \
	(PQresultStatus(result)!=expected) \
	{ fputs(PQerrorMessage(db),stderr); AT; goto label; } }while(0)

#endif

/*IN GOD WE TRVST.*/

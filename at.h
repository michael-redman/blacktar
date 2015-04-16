#ifndef __AT_H
#define __AT_H

#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)
#define AT "at " __FILE__ ": " TO_STRING(__LINE__) "\n"
#define AT_ERR fputs(AT,stderr);

#endif
//IN GOD WE TRVST.

prefix?=/usr/local
exec_prefix?=$(prefix)

CFLAGS=-Wall -g -I $(prefix)/include
LDFLAGS=-L $(prefix)/lib
PG_FLAGS=-I /usr/include/postgresql -lpq
QUERY_TYPE?=JOIN

LIBS=hmac_of_file noise
SCRIPTS=s3_list_keys retrieve

all: $(LIBS) restore

hmac_of_file: hmac_of_file_main.c
	cc $(CFLAGS) $(LDFLAGS) -lcrypto -lhexbytes -L $(exec_prefix)/lib/verity -lhmac_of_file -o $@ $<

noise: noise.c
	cc -Wall -g -o $@ $<

restore: restore.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(LDFLAGS) $(PG_FLAGS) -lfgetsnull -L $(exec_prefix)/lib/verity -lread_whole_file -o $@ $<

install:
	$(foreach prog, COPYRIGHT LICENSE README, install -D -m 0644 $(prog) $(prefix)/share/doc/blacktar/$(prog);)
	$(foreach prog, $(LIBS), install -D -m 0755 $(prog) $(exec_prefix)/lib/blacktar/$(prog);)
	$(foreach prog, $(SCRIPTS), install -D -m 0755 $(prog) $(prefix)/share/blacktar/$(prog);)
	$(foreach prog, backup restore list_cruft, install -D -m 0755 $(prog) $(exec_prefix)/bin/blacktar_$(prog);)

uninstall:
	rm -rf $(exec_prefix)/lib/blacktar
	$(foreach prog, backup restore list_cruft, rm -f $(exec_prefix)/bin/blacktar_$(prog);)
	rm -rf $(prefix)/share/doc/blacktar
	rm -rf $(prefix)/share/blacktar

clean:
	rm -f $(LIBS) restore

#IN GOD WE TRVST.

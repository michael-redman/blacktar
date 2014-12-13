prefix?=/usr/local
exec_prefix?=$(prefix)

CFLAGS=-Wall -g -I $(prefix)/include -I /usr/include/postgresql
LDFLAGS=-L $(prefix)/lib -lhexbytes -lfgetsnull -lpq 
QUERY_TYPE?=JOIN

PROGS=restore s3_hashes list_cruft
LIBS=hmacs_of_hashes noise
SCRIPTS=s3_list_keys retrieve

all: $(LIBS) $(PROGS)

hmacs_of_hashes: read_whole_file.c hmacs_of_hashes.c
	cc $(CFLAGS) $(LDFLAGS) -lcrypto -o $@ $^

noise: noise.c
	cc -Wall -g -o $@ $<

s3_hashes: s3_hashes.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(LDFLAGS) -o $@ $^

list_cruft: list_cruft.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(LDFLAGS) -o $@ $^

restore: restore.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(LDFLAGS) -o $@ $^

install:
	$(foreach prog, COPYRIGHT LICENSE README, install -D -m 0644 $(prog) $(prefix)/share/doc/blacktar/$(prog);)
	$(foreach prog, $(LIBS), install -D -m 0755 $(prog) $(exec_prefix)/lib/blacktar/$(prog);)
	$(foreach prog, $(SCRIPTS), install -D -m 0755 $(prog) $(prefix)/share/blacktar/$(prog);)
	$(foreach prog, backup $(PROGS), install -D -m 0755 $(prog) $(exec_prefix)/bin/blacktar_$(prog);)
	mkdir -p /var/local/blacktar

uninstall:
	rm -rf $(exec_prefix)/lib/blacktar
	$(foreach prog, backup restore list_cruft, rm -f $(exec_prefix)/bin/blacktar_$(prog);)
	rm -rf $(prefix)/share/doc/blacktar
	rm -rf $(prefix)/share/blacktar

clean:
	rm -f $(LIBS) $(PROGS)

#IN GOD WE TRVST.

prefix?=/usr/local
exec_prefix?=$(prefix)

CFLAGS=-Wall -g -fstack-protector -I $(prefix)/include
ECPG_CFLAGS=-I /usr/include/postgresql
LDFLAGS=-L $(prefix)/lib
LDADD=-lhexbytes -lfgetsnull -lpq 
QUERY_TYPE?=JOIN

PROGS=restore list_cruft
LIBS=hmacs_of_hashes hashes_of_hmacs noise
SCRIPTS=get_passphrase retrieve

all: $(LIBS) $(PROGS)

hmacs_of_hashes: read_whole_file.c hmacs_of_hashes.c
	cc $(CFLAGS) $(LDFLAGS) -lcrypto -lhexbytes -o $@ $^

list_cruft: list_cruft.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(ECPG_CFLAGS) $(LDFLAGS) $(LDADD) -o $@ $^

restore: restore.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(ECPG_CFLAGS) $(LDFLAGS) $(LDADD) -o $@ $^

install:
	$(foreach prog, COPYRIGHT LICENSE README, install -D -m 0644 $(prog) $(prefix)/share/doc/blacktar/$(prog);)
	$(foreach prog, $(LIBS), install -D -m 0755 $(prog) $(exec_prefix)/lib/blacktar/$(prog);)
	$(foreach prog, $(SCRIPTS), install -D -m 0755 $(prog) $(prefix)/share/blacktar/$(prog);)
	$(foreach prog, backup $(PROGS), install -D -m 0755 $(prog) $(exec_prefix)/bin/blacktar_$(prog);)
	install -m 0755 s3_list_keys $(exec_prefix)/bin/s3_list_keys
	mkdir -p /var/local/blacktar
	chmod +t /var/local/blacktar
	chmod go+rwx /var/local/blacktar

uninstall:
	rm -rf $(exec_prefix)/lib/blacktar
	$(foreach prog, backup $(PROGS), rm -f $(exec_prefix)/bin/blacktar_$(prog);)
	rm -f $(exec_prefix)/bin/blacktar
	rm -rf $(prefix)/share/doc/blacktar
	rm -rf $(prefix)/share/blacktar

clean:
	rm -f $(LIBS) $(PROGS)

#IN GOD WE TRVST.

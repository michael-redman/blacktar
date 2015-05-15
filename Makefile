prefix?=/usr/local
exec_prefix?=$(prefix)

CFLAGS=-Wall -g -fstack-protector -O2 -I $(prefix)/include
ECPG_CFLAGS=-I /usr/include/postgresql
LDFLAGS=-L $(prefix)/lib
LDADD=-lhexbytes -lpq 
QUERY_TYPE?=JOIN

PROGS=restore list_cruft
BIN_SCRIPTS=backup delta put_spool s3_list_keys s3_put
LIBEXECS=hmacs hashes noise paths
SHARE_SCRIPTS=get_passphrase retrieve schema.psql
MAN1=blacktar_backup.1 blacktar_restore.1 blacktar_list_cruft.1

all: $(LIBEXECS) $(PROGS)

hmacs: read_whole_file.c hmacs.c
	cc $(CFLAGS) $(LDFLAGS) -lcrypto -lhexbytes -o $@ $^

restore: restore.c read_whole_file.c
	cc -D$(QUERY_TYPE) $^ $(CFLAGS) $(ECPG_CFLAGS) $(LDFLAGS) $(LDADD) -lcrypto -o $@

list_cruft: list_cruft.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(ECPG_CFLAGS) $(LDFLAGS) $(LDADD) -o $@ $^ -lcrypto

install:
	$(foreach prog, COPYRIGHT LICENSE README, install -D -m 0644 $(prog) $(prefix)/share/doc/blacktar/$(prog);)
	$(foreach prog, $(MAN1), install -D -m 0644 $(prog) $(prefix)/share/man/man1/$(prog);)
	install -D -m 0644 blacktar.7 $(prefix)/share/man/man7/blacktar.7
	$(foreach prog, $(LIBEXECS), install -D -m 0755 $(prog) $(exec_prefix)/lib/blacktar/$(prog);)
	$(foreach prog, $(SHARE_SCRIPTS), install -D -m 0755 $(prog) $(prefix)/share/blacktar/$(prog);)
	$(foreach prog, $(BIN_SCRIPTS) $(PROGS), install -D -m 0755 $(prog) $(exec_prefix)/bin/blacktar_$(prog);)
	mkdir -p /var/local/cache/blacktar
	chmod +t /var/local/cache/blacktar
	chmod go+rwx /var/local/cache/blacktar

uninstall:
	rm -rf $(exec_prefix)/lib/blacktar
	$(foreach prog, $(PROGS) $(BIN_SCRIPTS), rm -f $(exec_prefix)/bin/blacktar_$(prog);)
	$(foreach prog, $(MAN1), rm -f $(prefix)/share/man/man1/$(prog);)
	rm $(prefix)/share/man/man7/blacktar.7
	rm -f $(exec_prefix)/bin/blacktar
	rm -rf $(prefix)/share/doc/blacktar
	rm -rf $(prefix)/share/blacktar
	rm -rf /var/local/cache/blacktar

clean:
	rm -f $(LIBEXECS) $(PROGS)

#IN GOD WE TRVST.

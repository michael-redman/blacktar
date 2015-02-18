prefix?=/usr/local
exec_prefix?=$(prefix)

CFLAGS=-Wall -g -fstack-protector -O2 -I $(prefix)/include
ECPG_CFLAGS=-I /usr/include/postgresql
LDFLAGS=-L $(prefix)/lib
LDADD=-lhexbytes -lfgetsnull -lpq 
QUERY_TYPE?=JOIN

PROGS=restore list_cruft
LIBEXECS=hmacs hashes noise paths
SCRIPTS=get_passphrase retrieve
MAN1=blacktar_backup.1 blacktar_restore.1 blacktar_list_cruft.1

all: $(LIBEXECS) $(PROGS)

hmacs: read_whole_file.c hmacs.c
	cc $(CFLAGS) $(LDFLAGS) -lcrypto -lhexbytes -o $@ $^

restore: restore.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(ECPG_CFLAGS) $(LDFLAGS) $(LDADD) -o $@ $^

list_cruft: list_cruft.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(ECPG_CFLAGS) $(LDFLAGS) $(LDADD) -o $@ $^

install:
	$(foreach prog, COPYRIGHT LICENSE README, install -D -m 0644 $(prog) $(prefix)/share/doc/blacktar/$(prog);)
	$(foreach prog, $(MAN1), install -D -m 0644 $(prog) $(prefix)/share/man/man1/$(prog);)
	install -D -m 0644 blacktar.7 $(prefix)/share/man/man7/blacktar.7
	$(foreach prog, $(LIBEXECS), install -D -m 0755 $(prog) $(exec_prefix)/lib/blacktar/$(prog);)
	$(foreach prog, $(SCRIPTS), install -D -m 0755 $(prog) $(prefix)/share/blacktar/$(prog);)
	$(foreach prog, backup $(PROGS), install -D -m 0755 $(prog) $(exec_prefix)/bin/blacktar_$(prog);)
	install -m 0755 s3_list_keys $(exec_prefix)/bin/s3_list_keys
	mkdir -p /var/local/cache/blacktar
	chmod +t /var/local/cache/blacktar
	chmod go+rwx /var/local/cache/blacktar

uninstall:
	rm -rf $(exec_prefix)/lib/blacktar
	$(foreach prog, backup $(PROGS), rm -f $(exec_prefix)/bin/blacktar_$(prog);)
	$(foreach prog, $(MAN1), rm -f $(prefix)/share/man/man1/$(prog);)
	rm $(prefix)/share/man/man7/blacktar.7
	rm -f $(exec_prefix)/bin/blacktar
	rm -rf $(prefix)/share/doc/blacktar
	rm -rf $(prefix)/share/blacktar
	rm -rf /var/local/cache/blacktar

clean:
	rm -f $(LIBEXECS) $(PROGS)

#IN GOD WE TRVST.

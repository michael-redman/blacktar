prefix?=/usr/local
exec_prefix?=$(prefix)

CFLAGS=-Wall -g -fstack-protector -O2 -I $(prefix)/include
PQ_CFLAGS=-I /usr/include/postgresql
LDFLAGS=-L $(prefix)/lib
LDADD=-lpq
QUERY_TYPE?=JOIN

PROGS=restore s3_list_cruft
BIN_SCRIPTS=backup db_delta s3_put_spool s3_list_keys s3_put
LIBEXECS=hmacs hashes noise paths
SHARE_SCRIPTS=get_passphrase retrieve schema.psql strip_s3_list
MAN1=verity_backup.1 verity_restore.1 verity_s3_list_cruft.1

all: $(LIBEXECS) $(PROGS)

hmacs: read_whole_file.c hmacs.c
	cc $(CFLAGS) $(LDFLAGS) -lcrypto -o $@ $^

restore: restore.c read_whole_file.c
	cc -D$(QUERY_TYPE) $^ $(CFLAGS) $(PQ_CFLAGS) $(LDFLAGS) $(LDADD) -lcrypto -o $@

s3_list_cruft: s3_list_cruft.c read_whole_file.c
	cc -D$(QUERY_TYPE) $(CFLAGS) $(PQ_CFLAGS) $(LDFLAGS) $(LDADD) -o $@ $^ -lcrypto

install:
	$(foreach prog, COPYRIGHT LICENSE README, install -D -m 0644 $(prog) $(prefix)/share/doc/verity-backup/$(prog);)
	$(foreach prog, $(MAN1), install -D -m 0644 $(prog) $(prefix)/share/man/man1/$(prog);)
	install -D -m 0644 verity-backup.7 $(prefix)/share/man/man7/verity-backup.7
	$(foreach prog, $(LIBEXECS), install -D -m 0755 $(prog) $(exec_prefix)/lib/verity-backup/$(prog);)
	$(foreach prog, $(SHARE_SCRIPTS), install -D -m 0755 $(prog) $(prefix)/share/verity-backup/$(prog);)
	$(foreach prog, $(BIN_SCRIPTS) $(PROGS), install -D -m 0755 $(prog) $(exec_prefix)/bin/verity_$(prog);)
	mkdir -p /var/local/cache/verity-backup
	chmod +t /var/local/cache/verity-backup
	chmod go+rwx /var/local/cache/verity-backup

uninstall:
	rm -rf $(exec_prefix)/lib/verity-backup
	$(foreach prog, $(PROGS) $(BIN_SCRIPTS), rm -f $(exec_prefix)/bin/verity_$(prog);)
	$(foreach prog, $(MAN1), rm -f $(prefix)/share/man/man1/$(prog);)
	rm $(prefix)/share/man/man7/verity-backup.7
	rm -rf $(prefix)/share/doc/verity-backup
	rm -rf $(prefix)/share/verity-backup
	rm -rf /var/local/cache/verity-backup

clean:
	rm -f $(LIBEXECS) $(PROGS)

#IN GOD WE TRVST.

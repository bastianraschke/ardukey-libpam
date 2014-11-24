LIBDIR = $(DESTDIR)/usr/lib/pam-ardukey
BINDIR = $(DESTDIR)/usr/bin

clean:
	rm -f *.py[co] */*.py[co]

install:
	mkdir -p $(LIBDIR)
	cp -r src/lib/ $(DESTDIR)/
	cp -r src/usr/ $(DESTDIR)/

uninstall:
	rm -rf $(LIBDIR)
	rm -f $(DESTDIR)/usr/share/pam-configs/ardukey
	rm -f $(BINDIR)/pam-ardukey-conf
	rm -f $(DESTDIR)/lib/security/pam_ardukey.py
	rm -f $(DESTDIR)/etc/bash_completion.d/pam-ardukey

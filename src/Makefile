LIBDIR = $(DESTDIR)/usr/lib/pamardukey
BINDIR = $(DESTDIR)/usr/bin

all:
	@echo "Try 'make install' or 'make clean'."
	@exit 1

clean:
	find files/ -name "*.pyc" -exec rm -rf {} \;
	rm -rf files/libraries/__pycache__/

install:
	install -D --mode 644 files/lib/security/pam_ardukey.py $(DESTDIR)/lib/security/pam_ardukey.py
	install -D --mode 644 files/etc/pam-ardukey.conf $(DESTDIR)/etc/pam-ardukey.conf
	install -D --mode 644 files/usr/lib/pamardukey/__init__.py $(LIBDIR)/__init__.py
	install -D --mode 644 files/usr/lib/pamardukey/Config.py $(LIBDIR)/Config.py
	install -D --mode 644 files/usr/lib/pamardukey/version.py $(LIBDIR)/version.py
	install -D --mode 644 files/usr/share/pam-configs/ardukey $(DESTDIR)/usr/share/pam-configs/ardukey
	install -D --mode 755 files/usr/bin/pam-ardukey-conf $(DESTDIR)/usr/bin/pam-ardukey-conf

uninstall:
	rm -rf $(LIBDIR)
	rm -f $(DESTDIR)/etc/pamardukey.conf
	rm -f $(DESTDIR)/usr/share/pam-configs/ardukey
	rm -f $(BINDIR)/pam-ardukey-conf
	rm -f $(DESTDIR)/lib/security/pam_ardukey.py

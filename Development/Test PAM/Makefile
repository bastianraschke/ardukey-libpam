clean:
	rm -f *.py[co] */*.py[co]

install:
	cp pam_test.py $(DESTDIR)/lib/security/
	cp test $(DESTDIR)/usr/share/pam-configs/
	pam-auth-update --package test

uninstall:
	pam-auth-update --package --remove test
	rm -f $(DESTDIR)/lib/security/pam_test.py
	rm -f $(DESTDIR)/usr/share/pam-configs/test

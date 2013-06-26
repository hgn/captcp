PREFIX=/usr

ALL: install

INSTALL = /usr/bin/install -c -m 0755
INSTALLDATA = /usr/bin/install -c -m 0644

install: captcp.py
	test -d $(DESTDIR)$(PREFIX) || mkdir -p $(DESTDIR)$(PREFIX)
	test -d $(DESTDIR)$(PREFIX)/bin || mkdir -p $(DESTDIR)$(PREFIX)/bin
	test -d $(DESTDIR)$(PREFIX)/share || mkdir -p $(DESTDIR)$(PREFIX)/share
	test -d $(DESTDIR)$(PREFIX)/share/captcp || mkdir -p $(DESTDIR)$(PREFIX)/share/captcp
	test -d $(DESTDIR)$(PREFIX)/share/captcp/data || mkdir -p $(DESTDIR)$(PREFIX)/share/captcp/data
	test -d $(DESTDIR)$(PREFIX)/share/captcp/data/stap-scripts || \
					mkdir -p $(DESTDIR)$(PREFIX)/share/captcp/data/stap-scripts
	test -d $(DESTDIR)$(PREFIX)/share/captcp/data/templates || \
					mkdir -p $(DESTDIR)$(PREFIX)/share/captcp/data/templates
	test -d $(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data || \
					mkdir -p $(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/
	test -d $(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/images || \
					mkdir -p $(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/images

	$(INSTALL) -m 0755 captcp.py $(DESTDIR)$(PREFIX)/share/captcp
	$(INSTALLDATA) data/stap-scripts/* $(DESTDIR)$(PREFIX)/share/captcp/data/stap-scripts
	$(INSTALLDATA) data/templates/* $(DESTDIR)$(PREFIX)/share/captcp/data/templates
	$(INSTALLDATA) data/connection-animation-data/captcp-anim.js \
					$(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/index.html \
					$(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/data.js \
					$(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/raphael-min.js \
					$(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/style.css \
					$(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/images/* \
					$(DESTDIR)$(PREFIX)/share/captcp/data/connection-animation-data/images/

	rm -f $(DESTDIR)$(PREFIX)/bin/captcp
	ln -s $(DESTDIR)$(PREFIX)/share/captcp/captcp.py $(DESTDIR)$(PREFIX)/bin/captcp

uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/share/captcp
	rm -rf $(DESTDIR)$(PREFIX)/bin/captcp

.PHONY: install uninstall

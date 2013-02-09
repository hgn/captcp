PREFIX=/usr

ALL: install


INSTALL = /usr/bin/install -c -m 0755
INSTALLDATA = /usr/bin/install -c -m 0644

install-man-page: man/captcp.1
	cat man/captcp.1 | gzip > man/captcp.1.gz
	$(INSTALL) man/captcp.1.gz $(PREFIX)/share/man/man1/
	rm -f man/captcp.1.gz

uninstall-man-page:
	rm -f $(PREFIX)/share/man/man1/captcp.1.gz

install: captcp.py install-man-page
	test -d $(PREFIX) || mkdir -p $(PREFIX)
	test -d $(PREFIX)/bin || mkdir -p $(PREFIX)/bin
	test -d $(PREFIX)/share || mkdir -p $(PREFIX)/share
	test -d $(PREFIX)/share/captcp || mkdir -p $(PREFIX)/share/captcp
	test -d $(PREFIX)/share/captcp/data || mkdir -p $(PREFIX)/share/captcp/data
	test -d $(PREFIX)/share/captcp/data/stap-scripts || \
					mkdir -p $(PREFIX)/share/captcp/data/stap-scripts
	test -d $(PREFIX)/share/captcp/data/templates || \
					mkdir -p $(PREFIX)/share/captcp/data/templates
	test -d $(PREFIX)/share/captcp/data/connection-animation-data || \
					mkdir -p $(PREFIX)/share/captcp/data/connection-animation-data/
	test -d $(PREFIX)/share/captcp/data/connection-animation-data/images || \
					mkdir -p $(PREFIX)/share/captcp/data/connection-animation-data/images

	$(INSTALL) -m 0755 captcp.py $(PREFIX)/share/captcp
	$(INSTALLDATA) data/stap-scripts/* $(PREFIX)/share/captcp/data/stap-scripts
	$(INSTALLDATA) data/templates/* $(PREFIX)/share/captcp/data/templates
	$(INSTALLDATA) data/connection-animation-data/captcp-anim.js \
					$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/index.html \
					$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/data.js \
					$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/raphael-min.js \
					$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/style.css \
					$(PREFIX)/share/captcp/data/connection-animation-data/
	$(INSTALLDATA) data/connection-animation-data/images/* \
					$(PREFIX)/share/captcp/data/connection-animation-data/images/

	rm -f $(PREFIX)/bin/captcp
	ln -s $(PREFIX)/share/captcp/captcp.py $(PREFIX)/bin/captcp

uninstall: uninstall-man-page
	rm -rf $(PREFIX)/share/captcp
	rm -rf $(PREFIX)/bin/captcp

help:
	@echo "What should I make? Valid targets are:"
	@echo "  install   - install all files, including man pages"
	@echo "  uninstall - cleanup everything" 


.PHONY: install uninstall help

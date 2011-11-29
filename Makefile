
prefix=/usr

INSTALL = /usr/bin/install -c -m 0755
INSTALLDATA = /usr/bin/install -c -m 0644


install: uninstall captcp.py
	test -d $(prefix) || mkdir $(prefix)
	test -d $(prefix)/share || mkdir $(prefix)/share
	test -d $(prefix)/captcp || mkdir $(prefix)/share/captcp
	test -d $(prefix)/captcp/data || mkdir $(prefix)/share/captcp/data

	$(INSTALL) -m 0755 captcp.py $(prefix)/share/captcp
	$(INSTALLDATA) data/* $(prefix)/share/captcp/data/

	ln -s $(prefix)/share/captcp/captcp.py $(prefix)/bin/captcp


uninstall:
	rm -rf $(prefix)/share/captcp
	rm -rf $(prefix)/bin/captcp


.PHONY: install uninstall

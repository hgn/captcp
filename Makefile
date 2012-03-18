
prefix=/usr

ALL: install

INSTALL = /usr/bin/install -c -m 0755
INSTALLDATA = /usr/bin/install -c -m 0644


install: captcp.py
	test -d $(prefix) || mkdir --parents $(prefix)
	test -d $(prefix)/share || mkdir --parents $(prefix)/share
	test -d $(prefix)/share/captcp || mkdir --parents $(prefix)/share/captcp
	test -d $(prefix)/share/captcp/data || mkdir --parents $(prefix)/share/captcp/data
	test -d $(prefix)/share/captcp/data/stap-scripts || mkdir --parents $(prefix)/share/captcp/data/stap-scripts
	test -d $(prefix)/share/captcp/data/templates || mkdir --parents $(prefix)/share/captcp/data/templates

	$(INSTALL) -m 0755 captcp.py $(prefix)/share/captcp
	$(INSTALLDATA) data/stap-scripts/* $(prefix)/share/captcp/data/stap-scripts
	$(INSTALLDATA) data/templates/* $(prefix)/share/captcp/data/templates

	rm -f $(prefix)/bin/captcp
	ln -s $(prefix)/share/captcp/captcp.py $(prefix)/bin/captcp


uninstall:
	rm -rf $(prefix)/share/captcp
	rm -rf $(prefix)/bin/captcp


.PHONY: install uninstall

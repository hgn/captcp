
prefix=/usr

INSTALL = /usr/bin/install -c -m 0755
INSTALLDATA = /usr/bin/install -c -m 0644


install: uninstall captcp.py
	test -d $(prefix) || mkdir $(prefix)
	test -d $(prefix)/share || mkdir $(prefix)/share
	test -d $(prefix)/captcp || mkdir $(prefix)/share/captcp
	test -d $(prefix)/captcp/data || mkdir $(prefix)/share/captcp/data
	test -d $(prefix)/captcp/data/stap-scripts || mkdir $(prefix)/share/captcp/data/stap-scripts
	test -d $(prefix)/captcp/data/templates || mkdir $(prefix)/share/captcp/data/templates

	$(INSTALL) -m 0755 captcp.py $(prefix)/share/captcp
	$(INSTALLDATA) data/stap-scripts/* $(prefix)/share/captcp/data/stap-scripts
	$(INSTALLDATA) data/templates/* $(prefix)/share/captcp/data/templates

	ln -s $(prefix)/share/captcp/captcp.py $(prefix)/bin/captcp


uninstall:
	rm -rf $(prefix)/share/captcp
	rm -rf $(prefix)/bin/captcp


.PHONY: install uninstall

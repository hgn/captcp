
BASEDIR=$(PWD)


SSH_HOST=jauu.net
SSH_USER=pfeifer
SSH_TARGET_DIR=/var/www/research.protocollabs.com/captcp

help:
	@echo 'Usage:                                                                '
	@echo '   ssh_upload                       upload the web site using SSH     '
	@echo '                                                                      '



ssh_upload:
	scp -r index.htm $(SSH_USER)@$(SSH_HOST):$(SSH_TARGET_DIR)
	#scp -r css $(SSH_USER)@$(SSH_HOST):$(SSH_TARGET_DIR)
	#scp -r data $(SSH_USER)@$(SSH_HOST):$(SSH_TARGET_DIR)
	#scp -r data-sound $(SSH_USER)@$(SSH_HOST):$(SSH_TARGET_DIR)
	#scp -r images $(SSH_USER)@$(SSH_HOST):$(SSH_TARGET_DIR)


.PHONY: ssh_upload 
    

#
# service_manager/Makefile
#
# Copyright (c) 2013 CradlePoint, Inc. <www.cradlepoint.com>.
# All rights reserved.
#
# This file contains confidential information of CradlePoint, Inc. and your 
# use of this file is subject to the CradlePoint Software License Agreement 
# distributed with this file. Unauthorized reproduction or distribution of 
# this file is subject to civil and criminal penalties.

ROOT ?= $(abspath ..)
include $(ROOT)/Makefile.config

TARBALL=wpc.tar.gz
INSTALL_PATH = $(INSTALL_ROOT)
VENV = .venv
PKG_REQS = requirements.txt

ifndef INSTALL_PATH
  $(error INSTALL_PATH is not defined. Did you forget to set ROME_S3_CONFIG_PAGES_DIR?)
endif


.PHONY: $(TARBALL)

all: $(TARBALL)

test: $(TARBALL)
ifndef CMS_HOST
	$(warning CMS_HOST is not defined - skipping ECM custom firmware update)
endif
ifndef TEST_PATH
	$(warning TEST_PATH is not defined - skipping Migration test update)
endif

	$(MAKE) -C ../service_manager cms
	python ECMTestFirmwareDeploy.py --ip=$(CMS_HOST) --test_path=$(TEST_PATH)


deploy: install $(TARBALL)
	@echo "Extracting to $(INSTALL_PATH)"
	cp $(TARBALL) $(INSTALL_PATH) && cd $(INSTALL_PATH) && tar -xzf $(TARBALL) && rm $(TARBALL)
	. $(VENV)/bin/activate && python refresh_firmware.py --host=$(WPC_HOST)":"$(WPC_PORT) build_info.txt

install: $(VENV) $(PKG_REQS)
	mkdir -p ~/.pip_cache
	. $(VENV)/bin/activate && pip install --upgrade distribute
	. $(VENV)/bin/activate && pip install -Ur $(PKG_REQS)
	touch $@

$(VENV):
	virtualenv --distribute $@ || rm -rf $@

$(TARBALL):
	../tools/bin/service_manager --version > build_info.txt 2>/dev/null
	cd packager && ./package.sh ../.. && mv $@ ../

clean:
	rm -f build_info.txt
	rm -f $(TARBALL)
	rm -rf $(VENV)

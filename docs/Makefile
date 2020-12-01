# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?= 
SPHINXBUILD   ?= sphinx-build -c .
SOURCEDIR     = .
BUILDDIR      = ./_build
APP = /app

.PHONY: help livehtml apidocs Makefile

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Build, watch and serve docs with live reload
livehtml:
	sphinx-autobuild -b html --host 0.0.0.0 --port 7000 --watch $(APP) -c . $(SOURCEDIR) $(BUILDDIR)/html

# Outputs rst files from django application code
apidocs:
	sphinx-apidoc -o $(SOURCEDIR)/api /app

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -b $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

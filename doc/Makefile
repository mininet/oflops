DOXYGEN = doxygen

PAPER=letter
EXTRACT_ALL=YES
EXTRACT_PRIVATE=YES
EXTRACT_STATIC=YES
HAVE_DOT=NO

.PHONY: help clean html latex images


EXTRA_DIST=doxygen.conf.in

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html      to make HTML files"
	@echo "  latex     to make LaTeX files, you can set PAPER=a4 or PAPER=letter"
	@echo "For both targets, you can set"
	@echo "  EXTRACT_ALL=YES/NO to extract all/documented functions"
	@echo "  EXTRACT_PRIVATE=YES/NO to extract private functions or not"
	@echo "  EXTRACT_STATIC=YES/NO to extract static functions"
	@echo "  HAVE_DOT=YES/NO to draw graphical graphs"

# nothing to do on all
all: 

docs: html latex



clean:
	rm -rf latex html

html:
	rm -rf html
	sed -e 's:^GENERATE_HTML *= NO:GENERATE_HTML = YES:' \
	    -e 's:^EXTRACT_ALL *= NO:EXTRACT_ALL = $(EXTRACT_ALL):'\
	    -e 's:^EXTRACT_PRIVATE *= NO:EXTRACT_PRIVATE = $(EXTRACT_PRIVATE):'\
	    -e 's:^EXTRACT_STATIC *= NO:EXTRACT_STATIC = $(EXTRACT_STATIC):'\
	    -e 's:^HAVE_DOT *= NO:HAVE_DOT = $(HAVE_DOT):'\
	    < doxygen.conf | $(DOXYGEN) -

latex:
	rm -rf latex
	sed -e 's:^GENERATE_LATEX *= NO:GENERATE_LATEX = YES:' \
	    -e 's:^EXTRACT_ALL *= NO:EXTRACT_ALL = $(EXTRACT_ALL):'\
	    -e 's:^EXTRACT_PRIVATE *= NO:EXTRACT_PRIVATE = $(EXTRACT_PRIVATE):'\
	    -e 's:^EXTRACT_STATIC *= NO:EXTRACT_STATIC = $(EXTRACT_STATIC):'\
	    -e 's:^HAVE_DOT *= NO:HAVE_DOT = $(HAVE_DOT):'\
	    -e 's:^PAPER_TYPE *= letter:PAPER_TYPE = $(PAPER):'\
	    < doxygen.conf | $(DOXYGEN) -
	(cd latex && make pdf)

install:

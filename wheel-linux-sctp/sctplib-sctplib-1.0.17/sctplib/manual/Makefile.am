EXTRA_DIST = fixunder.sty functions.sty sctp-api.pdf \
             sctp-api.ps sctp-api.tex commands.doc \
             commands.html commands.pdf 

all:

clean:
	rm -f *.toc *.log *.idx *.ind *.aux *~

distclean:
	rm -f *.toc *.log *.idx *.ind *.aux *~ *.dvi

really-clean: clean
	rm -f *.dvi *.ps *.pdf

sctp-api.ps: sctp-api.pdf
	pdf2ps sctp-api.pdf sctp-api.ps

sctp-api.pdf: sctp-api.tex
	pdflatex sctp-api.tex
	pdflatex sctp-api.tex

dis: sctp-api.pdf
	acroread sctp-api.pdf

pdf: sctp-api.pdf

ps: sctp-api.ps

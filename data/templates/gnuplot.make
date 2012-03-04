GNUPLOT_FILES = $(wildcard *.gpi)
PNG_OBJ = $(patsubst %.gpi,%.png,  $(GNUPLOT_FILES))
PDF_OBJ = $(patsubst %.gpi,%.pdf,  $(GNUPLOT_FILES))

all: $(PDF_OBJ)
png: $(PNG_OBJ)

%.eps: %.gpi *.data
	@ echo "compillation of "$<
	@gnuplot $<

%.pdf: %.eps
	@echo "conversion in pdf format"
	@epstopdf --outfile=$*.pdf $<
	@echo "end"

%.png: %.pdf
	@echo "conversion in png format"
	@convert -density 300 $< $*.png 
	@echo "end"

preview: all
	for i in $$(ls *.pdf); do xpdf -fullscreen $$i ; done

clean:
	@echo "cleaning ..."
	@rm -rf *.eps *.png *.pdf core

distclean: clean
	@echo "distcleaning"
	@rm -rf *.data


pdf:
	a2x -fpdf -dbook --fop captcp.txt

webpage:
	a2x --format=xhtml --xsltproc-opts "--stringparam part.autolabel 0 --stringparam chapter.autolabel 0 --stringparam section.autolabel.max.depth 0 --stringparam toc.section.depth 1" --stylesheet css/style.css captcp.txt


clean:
	rm -rf *.html

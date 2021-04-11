TEX := pdflatex
OBJECT := FinalReport

all: report

report:
	${TEX} ${OBJECT}.tex
	biber ${OBJECT}
	${TEX} ${OBJECT}.tex
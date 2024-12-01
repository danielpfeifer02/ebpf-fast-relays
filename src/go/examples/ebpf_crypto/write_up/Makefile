# Makefile to compile main.tex

BUILD_DIR = build

all: $(BUILD_DIR)/main.pdf

$(BUILD_DIR)/main.pdf: main.tex
	cp bibliography.bib $(BUILD_DIR)
	pdflatex -output-directory=$(BUILD_DIR) main.tex
	cd $(BUILD_DIR) && bibtex main
	pdflatex -output-directory=$(BUILD_DIR) main.tex
	rm -f $(BUILD_DIR)/*.aux $(BUILD_DIR)/*.log $(BUILD_DIR)/*.out $(BUILD_DIR)/*.toc $(BUILD_DIR)/*.bbl $(BUILD_DIR)/*.blg $(BUILD_DIR)/*.bib $(BUILD_DIR)/*.bcf $(BUILD_DIR)/*.run.xml

clean:
	rm -rf $(BUILD_DIR)/*

.PHONY: all clean
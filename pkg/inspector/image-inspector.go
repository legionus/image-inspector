package inspector

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/openshift/image-inspector/pkg/openscap"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
)

// ImageInspector is the interface for all image inspectors.
type ImageInspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect() error
}

// openscapImageInspector is the openscap implementation of ImageInspector.
type openscapImageInspector struct {
	opts           iicmd.ImageInspectorOptions
	meta           *InspectorMetadata
	scanReport     []byte
	htmlScanReport []byte
}

// NewOpenscapImageInspector provides a new openscap inspector.
func NewOpenscapImageInspector(opts iicmd.ImageInspectorOptions, meta *InspectorMetadata) ImageInspector {
	i := &openscapImageInspector{
		opts: opts,
		meta: meta,
	}

	http.HandleFunc(OPENSCAP_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
		switch i.meta.OpenSCAP.Status {
		case StatusSuccess:
			w.Write(i.scanReport)
		case StatusError:
			http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", i.meta.OpenSCAP.ErrorMessage),
				http.StatusInternalServerError)
		}
	})

	http.HandleFunc(OPENSCAP_REPORT_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
		if !opts.OpenScapHTML {
			http.Error(w, "-openscap-html-report option was not chosen", http.StatusNotFound)
			return
		}
		switch i.meta.OpenSCAP.Status {
		case StatusSuccess:
			w.Write(i.htmlScanReport)
		case StatusError:
			http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", i.meta.OpenSCAP.ErrorMessage),
				http.StatusInternalServerError)
		}
	})

	return i
}

// Inspect inspects and serves the image based on the ImageInspectorOptions.
func (i *openscapImageInspector) Inspect() error {
	var err error

	if i.opts.ScanResultsDir, err = createOutputDir(i.opts.ScanResultsDir, "image-inspector-scan-results-"); err != nil {
		return err
	}

	scanner := openscap.NewDefaultScanner(OSCAP_CVE_DIR, i.opts.ScanResultsDir, i.opts.CVEUrlPath, i.opts.OpenScapHTML)

	i.scanReport, i.htmlScanReport, err = i.scanImage(scanner)
	if err != nil {
		i.meta.OpenSCAP.SetError(err)
		log.Printf("Unable to scan image: %v", err)
	} else {
		i.meta.OpenSCAP.Status = StatusSuccess
	}

	return nil
}

func (i *openscapImageInspector) scanImage(s openscap.Scanner) ([]byte, []byte, error) {
	log.Printf("%s scanning %s. Placing results in %s",
		s.ScannerName(), i.opts.DstPath, i.opts.ScanResultsDir)
	var htmlScanReport []byte
	err := s.Scan(i.opts.DstPath, &i.meta.Image)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to run %s: %v\n", s.ScannerName(), err)
	}
	scanReport, err := ioutil.ReadFile(s.ResultsFileName())
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s result file: %v\n", s.ScannerName(), err)
	}

	if i.opts.OpenScapHTML {
		htmlScanReport, err = ioutil.ReadFile(s.HTMLResultsFileName())
		if err != nil {
			return []byte(""), []byte(""), fmt.Errorf("Unable to read %s HTML result file: %v\n", s.ScannerName(), err)
		}
	}

	return scanReport, htmlScanReport, nil
}

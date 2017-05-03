package main

import (
	"flag"
	"fmt"
	"log"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
	ii "github.com/openshift/image-inspector/pkg/inspector"
)

func main() {
	inspectorOptions := iicmd.NewDefaultImageInspectorOptions()

	flag.StringVar(&inspectorOptions.URI, "docker", inspectorOptions.URI, "Daemon socket to connect to")
	flag.StringVar(&inspectorOptions.Image, "image", inspectorOptions.Image, "Docker image to inspect")
	flag.StringVar(&inspectorOptions.Container, "container", inspectorOptions.Container, "Container to inspect")
	flag.BoolVar(&inspectorOptions.Webdav, "webdav", inspectorOptions.Webdav, "Serve webdav via Image Inspector API service")
	flag.StringVar(&inspectorOptions.Volume, "volume", inspectorOptions.Volume, "Volume to inspect")
	flag.StringVar(&inspectorOptions.CustomScanConf, "custom", inspectorOptions.CustomScanConf, "YAML config file for custom scan types")
	flag.StringVar(&inspectorOptions.DstPath, "path", inspectorOptions.DstPath, "Destination path for the image files")
	flag.StringVar(&inspectorOptions.Serve, "serve", inspectorOptions.Serve, "Host and port to listen on for Image Inspector API service")
	flag.BoolVar(&inspectorOptions.Chroot, "chroot", inspectorOptions.Chroot, "Change root when serving the image with webdav")
	flag.Var(&inspectorOptions.DockerCfg, "dockercfg", "Location of the docker configuration files. May be specified more than once")
	flag.StringVar(&inspectorOptions.Username, "username", inspectorOptions.Username, "username for authenticating with the docker registry")
	flag.StringVar(&inspectorOptions.PasswordFile, "password-file", inspectorOptions.PasswordFile, "Location of a file that contains the password for authentication with the docker registry")
	flag.Var(&inspectorOptions.ScanType, "scan-type", fmt.Sprintf("The type of the scan to be done on the inspected image. May be specified more than once. Available scan types are: %v", iicmd.ScanOptions))
	flag.StringVar(&inspectorOptions.ScanResultsDir, "scan-results-dir", inspectorOptions.ScanResultsDir, "The directory that will contain the results of the scan")
	flag.BoolVar(&inspectorOptions.OpenScapHTML, "openscap-html-report", inspectorOptions.OpenScapHTML, "Generate an OpenScap HTML report in addition to the ARF formatted report")
	flag.StringVar(&inspectorOptions.CVEUrlPath, "cve-url", inspectorOptions.CVEUrlPath, "An alternative URL source for CVE files")

	flag.Parse()

	if err := inspectorOptions.Validate(); err != nil {
		log.Fatal(err)
	}

	if len(inspectorOptions.Image) > 0 {
		receiver := ii.NewImageReceiver(*inspectorOptions)

		meta, err := receiver.ExtractImage()
		if err != nil {
			log.Fatalf("Unable to extract image: %v", err)
		}

		if inspectorOptions.ScanType.HasValue("openscap") {
			openscapInspector := ii.NewOpenscapImageInspector(*inspectorOptions, meta)
			if err := openscapInspector.Inspect(); err != nil {
				log.Fatalf("Error inspecting image: %v", err)
			}
		}

		for _, scannerName := range iicmd.ScanOptions {
			if scannerName == "openscap" || !inspectorOptions.ScanType.HasValue(scannerName) {
				continue
			}
			ii.RunScanner(*inspectorOptions, scannerName, ii.ScannerImage)
		}

		if len(inspectorOptions.Serve) > 0 {
			if err := ii.Serve(*inspectorOptions, meta); err != nil {
				log.Fatalf("Image Inspector service failed: %v", err)
			}
		}
	} else if len(inspectorOptions.Volume) > 0 {
		log.Println("Scanning volume")
	} else {
		log.Println("Nothing to do!")
	}
}

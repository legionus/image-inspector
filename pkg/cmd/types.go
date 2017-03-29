package cmd

import (
	"fmt"
	"github.com/ghodss/yaml"
	oscapscanner "github.com/openshift/image-inspector/pkg/openscap"
	"os"
)

var (
	ScanOptions = []string{"openscap"}
)

type CustomScanOptions []struct {
	Name          string   `json:"name"`
	ImageScan     []string `json:"imagescan"`
	ContainerScan []string `json:"containerscan"`
	VolumeScan    []string `json:"volumescan"`
}

// MultiStringVar is implementing flag.Value
type MultiStringVar struct {
	Values []string
}

func (sv *MultiStringVar) Set(s string) error {
	sv.Values = append(sv.Values, s)
	return nil
}

func (sv *MultiStringVar) String() string {
	return fmt.Sprintf("%v", sv.Values)
}

func (sv *MultiStringVar) HasValue(s string) bool {
	for _, v := range sv.Values {
		if v == s {
			return true
		}
	}
	return false
}

// ImageInspectorOptions is the main inspector implementation and holds the configuration
// for an image inspector.
type ImageInspectorOptions struct {
	// ConfigFilePath contains the path to the YAML config file
	ConfigFilePath string
	// URI contains the location of the docker daemon socket to connect to.
	URI string
	// Image contains the docker image to inspect.
	Image string
	// Container contains the docker container to inspect.
	Container string
	// Volume contains the path to a volume to inspect.
	Volume string
	// CustomScanConf is the path to a YAML file to configure custom scan types
	CustomScanConf string
	// DstPath is the destination path for image files.
	DstPath string
	// Serve holds the host and port where the API service should listen.
	Serve string
	// Webdav controls whether or not to serve the image/container/volume via webdav
	Webdav bool
	// Chroot controls whether or not a chroot is excuted when serving the image with webdav.
	Chroot bool
	// DockerCfg is the location of the docker config file.
	DockerCfg MultiStringVar
	// Username is the username for authenticating to the docker registry.
	Username string
	// PasswordFile is the location of the file containing the password for authentication to the
	// docker registry.
	PasswordFile string
	// ScanType is the type of the scan to be done on the inspected image
	ScanType MultiStringVar
	// ScanResultsDir is the directory that will contain the results of the scan
	ScanResultsDir string
	// OpenScapHTML controls whether or not to generate an HTML report
	OpenScapHTML bool
	// CVEUrlPath An alternative source for the cve files
	CVEUrlPath string
	// CustomScans is a list of custom scan types and their configurations
	CustomScans CustomScanOptions
}

// NewDefaultImageInspectorOptions provides a new ImageInspectorOptions with default values.
func NewDefaultImageInspectorOptions() *ImageInspectorOptions {
	return &ImageInspectorOptions{
		ConfigFilePath: "",
		URI:            "unix:///var/run/docker.sock",
		Image:          "",
		Container:      "",
		Volume:         "",
		CustomScanConf: "",
		DstPath:        "",
		Serve:          "",
		Webdav:         false,
		Chroot:         false,
		DockerCfg:      MultiStringVar{[]string{}},
		Username:       "",
		PasswordFile:   "",
		ScanType:       MultiStringVar{[]string{}},
		ScanResultsDir: "",
		OpenScapHTML:   false,
		CVEUrlPath:     oscapscanner.CVEUrl,
		CustomScans:    nil,
	}
}

// Validate performs validation on the field settings.
func (i *ImageInspectorOptions) Validate() error {
	if len(i.URI) == 0 {
		return fmt.Errorf("Docker socket connection must be specified")
	}
	if len(i.Image)+len(i.Container)+len(i.Volume)+len(i.Serve) == 0 {
		return fmt.Errorf("Nothing to do! At least one of --serve, --image, --container, --volume must be specified.")
	}
	if len(i.DockerCfg.Values) > 0 && len(i.Username) > 0 {
		return fmt.Errorf("Only specify dockercfg file or username/password pair for authentication")
	}
	if len(i.Username) > 0 && len(i.PasswordFile) == 0 {
		return fmt.Errorf("Please specify password for the username")
	}
	if len(i.Serve) == 0 && i.Webdav {
		return fmt.Errorf("Webdav can only be enabled when the API service is enabled")
	}
	if !i.Webdav && i.Chroot {
		return fmt.Errorf("Change root can be used only when serving the image through webdav")
	}
	if len(i.ScanResultsDir) > 0 && len(i.ScanType.Values) == 0 {
		return fmt.Errorf("scan-result-dir can be used only when spacifing scan-type")
	}
	if len(i.ScanResultsDir) > 0 {
		fi, err := os.Stat(i.ScanResultsDir)
		if err == nil && !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", i.ScanResultsDir)
		}
	}
	if i.OpenScapHTML && !i.ScanType.HasValue("openscap") {
		return fmt.Errorf("OpenScapHtml can be used only when specifying scan-type as \"openscap\"")
	}
	for _, fl := range append(i.DockerCfg.Values, i.PasswordFile, i.CustomScanConf) {
		if len(fl) > 0 {
			if _, err := os.Stat(fl); os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist", fl)
			}
		}
	}
	if len(i.CustomScanConf) != 0 {
		// FIXME: make this come from the file instead of having it hard-coded here
		data := []byte(`
- name: occlamdscan
  imagescan: ['occlamdscan', '--image']
  containerscan: ['occlamdscan', '--container']
  volumescan: ['occlamdscan', '--volume']
`)
		if err := yaml.Unmarshal(data, &i.CustomScans); err != nil {
			return fmt.Errorf("Failed to parse scan option file %s already specified", i.CustomScanConf)
		}
		scanNames := map[string]bool{}
		for _, name := range ScanOptions {
			scanNames[name] = true
		}
		for _, custom := range i.CustomScans {
			if scanNames[custom.Name] {
				return fmt.Errorf("Custom scan option %s already specified", custom.Name)
			} else {
				scanNames[custom.Name] = true
				ScanOptions = append(ScanOptions, custom.Name)
			}
		}
	}
	for _, scantype := range i.ScanType.Values {
		var found bool = false
		for _, opt := range ScanOptions {
			if scantype == opt {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s is not one of the available scan-types which are %v", scantype, ScanOptions)
		}
	}
	return nil
}

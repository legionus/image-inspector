package inspector

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"syscall"

	"golang.org/x/net/webdav"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
)

type APIVersions struct {
	Versions []string `json:"versions"`
}

const (
	VERSION_TAG              = "v1"
	DOCKER_TAR_PREFIX        = "rootfs/"
	OWNER_PERM_RW            = 0600
	HEALTHZ_URL_PATH         = "/healthz"
	API_URL_PREFIX           = "/api"
	CONTENT_URL_PREFIX       = API_URL_PREFIX + "/" + VERSION_TAG + "/content/"
	METADATA_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/metadata"
	OPENSCAP_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap"
	OPENSCAP_REPORT_URL_PATH = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap-report"
	CHROOT_SERVE_PATH        = "/"
	OSCAP_CVE_DIR            = "/tmp"
	PULL_LOG_INTERVAL_SEC    = 10
)

func Serve(opts iicmd.ImageInspectorOptions, meta *InspectorMetadata) error {
	supportedVersions := APIVersions{Versions: []string{VERSION_TAG}}

	servePath := opts.DstPath
	if opts.Chroot {
		if err := syscall.Chroot(opts.DstPath); err != nil {
			return fmt.Errorf("Unable to chroot into %s: %v\n", opts.DstPath, err)
		}
		servePath = CHROOT_SERVE_PATH
	} else {
		log.Printf("!!!WARNING!!! It is insecure to serve the image content without changing")
		log.Printf("root (--chroot). Absolute-path symlinks in the image can lead to disclose")
		log.Printf("information of the hosting system.")
	}

	http.HandleFunc(HEALTHZ_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc(API_URL_PREFIX, func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(supportedVersions, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	})

	http.HandleFunc(METADATA_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	})

	if opts.Webdav {
		log.Printf("Serving image content %s on webdav://%s%s", opts.DstPath, opts.Serve, CONTENT_URL_PREFIX)

		http.Handle(CONTENT_URL_PREFIX, &webdav.Handler{
			Prefix:     CONTENT_URL_PREFIX,
			FileSystem: webdav.Dir(servePath),
			LockSystem: webdav.NewMemLS(),
		})
	}

	return http.ListenAndServe(opts.Serve, nil)
}

package inspector

import (
	"fmt"
	"os"
	"os/exec"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
)

const (
	ScannerImage     = "imagescan"
	ScannerVolume    = "volumescan"
	ScannerContainer = "containerscan"
)

func RunScanner(opts iicmd.ImageInspectorOptions, scanName, scanType string) error {
	for _, scanner := range opts.CustomScans {
		if scanner.Name != scanName {
			continue
		}

		var scanCommand, env []string

		switch scanType {
		case ScannerImage:
			scanCommand = scanner.ImageScan

			env = append(env, fmt.Sprintf("IMAGE_NAME=%s", opts.Image))
			env = append(env, fmt.Sprintf("IMAGE_PATH=%s", opts.DstPath))

		case ScannerVolume:
			scanCommand = scanner.VolumeScan

			env = append(env, fmt.Sprintf("VOLUME_PATH=%s", opts.Volume))

		case ScannerContainer:
			scanCommand = scanner.ContainerScan

			env = append(env, fmt.Sprintf("CONTAINER_NAME=%s", opts.Container))

		default:
			return fmt.Errorf("Unsupported scanner %q in %q", scanType, scanName)
		}

		if len(scanCommand) == 0 {
			return fmt.Errorf("Command not specified for scanner %q in %q", scanType, scanName)
		}

		return runCommand(opts, scanCommand, env)
	}

	return fmt.Errorf("Scanner %q not found", scanName)
}

func runCommand(opts iicmd.ImageInspectorOptions, command []string, env []string) error {
	cmd := exec.Command(command[0], command[1:]...)

	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

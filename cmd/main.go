package main

import (
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

func main() {
	// Initialize command line flags
	fs := pflag.NewFlagSet("aws-ebs-csi-driver", pflag.ExitOnError)

	// Create an instance of the cloud provider
	//cloud, err := cloud.NewCloud() // pass in options here, not specific ones

	// Parse command line options
	//options := GetOptions(fs)
	klog.InfoS("Starting the AWS EBS CSI driver", "options", options)

	// d, err := driver.NewDriver(cloud, options)
	// if err != nil {
	// 	klog.ErrorS(err, "Failed to create the AWS EBS CSI driver")
	// 	os.Exit(1)
	// }

	// err = d.Run()
	// if err != nil {
	// 	klog.ErrorS(err, "Failed to run the AWS EBS CSI driver")
	// 	os.Exit(1)
	// }
}

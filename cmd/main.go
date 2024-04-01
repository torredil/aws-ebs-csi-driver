package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kubernetes-sigs/aws-ebs-csi-driver/cmd/hooks"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/cloud"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/cloud/metadata"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/driver"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/metrics"
	flag "github.com/spf13/pflag"
	"k8s.io/component-base/featuregate"
	logsapi "k8s.io/component-base/logs/api/v1"
	json "k8s.io/component-base/logs/json"
	"k8s.io/klog/v2"
)

var (
	osExit      = os.Exit
	featureGate = featuregate.NewFeatureGate()
)

func main() {
	fs := flag.NewFlagSet("aws-ebs-csi-driver", flag.ExitOnError)
	if err := logsapi.RegisterLogFormat(logsapi.JSONLogFormat, json.Factory{}, logsapi.LoggingBetaOptions); err != nil {
		klog.ErrorS(err, "failed to register JSON log format")
	}

	var (
		version  = fs.Bool("version", false, "Print the version and exit.")
		toStderr = fs.Bool("logtostderr", false, "log to standard error instead of files. DEPRECATED: will be removed in a future release.")
		args     = os.Args[1:]
		cmd      = string(driver.AllMode)
		options  = driver.Options{}
	)

	options.AddFlags(fs)

	c := logsapi.NewLoggingConfiguration()
	err := logsapi.AddFeatureGates(featureGate)
	if err != nil {
		klog.ErrorS(err, "failed to add feature gates")
	}
	logsapi.AddFlags(c, fs)

	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		cmd = os.Args[1]
		args = os.Args[2:]
	}

	switch cmd {
	case "pre-stop-hook":
		clientset, clientErr := metadata.DefaultKubernetesAPIClient()
		if clientErr != nil {
			klog.ErrorS(err, "unable to communicate with k8s API")
		} else {
			err = hooks.PreStop(clientset)
			if err != nil {
				klog.ErrorS(err, "failed to execute PreStop lifecycle hook")
				klog.FlushAndExit(klog.ExitFlushTimeout, 1)
			}
		}
		klog.FlushAndExit(klog.ExitFlushTimeout, 0)
	case string(driver.ControllerMode), string(driver.NodeMode), string(driver.AllMode):
		options.DriverMode = driver.Mode(cmd)
	default:
		klog.Errorf("Unknown driver mode %s: Expected %s, %s, %s, or pre-stop-hook", cmd, driver.ControllerMode, driver.NodeMode, driver.AllMode)
		klog.FlushAndExit(klog.ExitFlushTimeout, 0)
	}

	if err = fs.Parse(args); err != nil {
		panic(err)
	}

	err = logsapi.ValidateAndApply(c, featureGate)
	if err != nil {
		klog.ErrorS(err, "failed to validate and apply logging configuration")
	}

	if *version {
		versionInfo, err := driver.GetVersionJSON()
		if err != nil {
			klog.ErrorS(err, "failed to get version")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
		fmt.Println(versionInfo)
		osExit(0)
	}

	if *toStderr {
		klog.SetOutput(os.Stderr)
	}

	// Start tracing as soon as possible
	if options.EnableOtelTracing {
		exporter, err := driver.InitOtelTracing()
		if err != nil {
			klog.ErrorS(err, "failed to initialize otel tracing")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}

		// Exporter will flush traces on shutdown
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := exporter.Shutdown(ctx); err != nil {
				klog.ErrorS(err, "could not shutdown otel exporter")
			}
		}()
	}

	if options.HttpEndpoint != "" {
		r := metrics.InitializeRecorder()
		r.InitializeMetricsHandler(options.HttpEndpoint, "/metrics")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		klog.V(5).InfoS("[Debug] Retrieving region from metadata service")
		metadataService, err := metadata.NewMetadataService(metadata.MetadataServiceConfig{
			EC2MetadataClient: metadata.DefaultEC2MetadataClient,
			K8sAPIClient:      metadata.DefaultKubernetesAPIClient,
		}, region)
		if err != nil {
			klog.ErrorS(err, "Could not determine region from any metadata service. The region can be manually supplied via the AWS_REGION environment variable.")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
		region = metadataService.GetRegion()
	}

	cloudService, err := cloud.NewCloud(region, options.AwsSdkDebugLog, options.UserAgentExtra, options.Batching)
	if err != nil {
		klog.ErrorS(err, "failed to create cloud service")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	metadataService, err := metadata.NewMetadataService(metadata.MetadataServiceConfig{
		EC2MetadataClient: metadata.DefaultEC2MetadataClient,
		K8sAPIClient:      metadata.DefaultKubernetesAPIClient,
	}, region)
	if err != nil {
		klog.ErrorS(err, "failed to create metadata service")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	drv, err := driver.NewDriver(&options, cloudService, metadataService, metadata.DefaultKubernetesAPIClient)
	if err != nil {
		klog.ErrorS(err, "failed to create driver")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	if err := drv.Run(); err != nil {
		klog.ErrorS(err, "failed to run driver")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}
}

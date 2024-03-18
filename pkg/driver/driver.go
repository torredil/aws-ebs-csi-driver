/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package driver

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/awslabs/volume-modifier-for-k8s/pkg/rpc"
	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/cloud"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/driver/controller"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/driver/identity"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/driver/node"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/metrics"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/util"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"k8s.io/component-base/logs/json"
	"k8s.io/klog/v2"

	logsapi "k8s.io/component-base/logs/api/v1"
)

// Mode is the operating mode of the CSI driver.
type Mode string

const (
	// ControllerMode is the mode that only starts the controller service.
	ControllerMode Mode = "controller"
	// NodeMode is the mode that only starts the node service.
	NodeMode Mode = "node"
	// AllMode is the mode that only starts both the controller and the node service.
	AllMode Mode = "all"

	DefaultModifyVolumeRequestHandlerTimeout = 2 * time.Second
)

type Driver struct {
	Controller *controller.Controller
	Node       *node.NodeService

	srv     *grpc.Server
	options *DriverOptions
}

type DriverOptions struct {
	endpoint                          string
	extraTags                         map[string]string
	mode                              Mode
	volumeAttachLimit                 int64
	reservedVolumeAttachments         int
	kubernetesClusterID               string
	awsSdkDebugLog                    bool
	batching                          bool
	warnOnInvalidTag                  bool
	userAgentExtra                    string
	otelTracing                       bool
	modifyVolumeRequestHandlerTimeout time.Duration
}

func NewDriver(c cloud.Cloud, options ...func(*DriverOptions)) (*Driver, error) {
	driverName := util.DriverName
	driverVersion := identity.GetVersion()

	klog.InfoS("Driver Information", "Driver", driverName, "Version", driverVersion)

	o := DriverOptions{
		endpoint:                          util.DefaultCSIEndpoint,
		mode:                              AllMode,
		modifyVolumeRequestHandlerTimeout: DefaultModifyVolumeRequestHandlerTimeout,
	}
	for _, option := range options {
		option(&o)
	}

	driver := Driver{
		options: &o,
	}

	// Register JSON logging format
	if err := logsapi.RegisterLogFormat(logsapi.JSONLogFormat, json.Factory{}, logsapi.LoggingBetaOptions); err != nil {
		klog.ErrorS(err, "Failed to register JSON log format")
		os.Exit(1)
	}

	// Initialize OpenTelemetry tracing
	//if options.ServerOptions.EnableOtelTracing {
	//	initTracing()
	//}

	// Setup and start metrics server if endpoint is set
	//if options.ServerOptions.HttpEndpoint != "" {
	//	setupMetricsServer(options.ServerOptions.HttpEndpoint)
	//}

	switch o.mode {
	case ControllerMode:
		driver.Controller = controller.NewController(c, &controller.Options{
			KubernetesClusterID: o.kubernetesClusterID,
			AwsSdkDebugLog:      o.awsSdkDebugLog,
			Batching:            o.batching,
			WarnOnInvalidTag:    o.warnOnInvalidTag,
			ExtraTags:           o.extraTags,
		})
	case NodeMode:
		driver.Node, _ = node.NewNodeService(&node.NodeOptions{
			Region: "us-west-2",
		})
	default:
		driver.Controller = controller.NewController(c, &controller.Options{
			Batching: false,
		})
		driver.Node, _ = node.NewNodeService(&node.NodeOptions{
			Region: "us-west-2",
		})
	}

	return &driver, nil
}

func initTracing() {
	exporter, err := InitOtelTracing()
	if err != nil {
		klog.ErrorS(err, "Failed to initialize OpenTelemetry tracing")
		os.Exit(1)
	}

	// Ensure traces are flushed before exiting
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := exporter.Shutdown(ctx); err != nil {
			klog.ErrorS(err, "Failed to shutdown OpenTelemetry exporter")
		}
	}()
}

func setupMetricsServer(endpoint string) {
	recorder := metrics.InitializeRecorder()
	recorder.InitializeMetricsHandler(endpoint, "/metrics")
}

func (d *Driver) Run() error {
	scheme, addr, err := util.ParseEndpoint(d.options.endpoint)
	if err != nil {
		return err
	}

	listener, err := net.Listen(scheme, addr)
	if err != nil {
		return err
	}

	logErr := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		if err != nil {
			klog.ErrorS(err, "GRPC error")
		}
		return resp, err
	}

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(logErr),
	}
	if d.options.otelTracing {
		opts = append(opts, grpc.StatsHandler(otelgrpc.NewServerHandler()))
	}
	d.srv = grpc.NewServer(opts...)

	identityService := &identity.Service{}
	csi.RegisterIdentityServer(d.srv, identityService)

	switch d.options.mode {
	case ControllerMode:
		csi.RegisterControllerServer(d.srv, d.Controller)
		rpc.RegisterModifyServer(d.srv, d.Controller)
	case NodeMode:
		csi.RegisterNodeServer(d.srv, d.Node)
	case AllMode:
		csi.RegisterControllerServer(d.srv, d.Controller)
		csi.RegisterNodeServer(d.srv, d.Node)
		rpc.RegisterModifyServer(d.srv, d.Controller)
	default:
		return fmt.Errorf("unknown mode: %s", d.options.mode)
	}

	klog.V(4).InfoS("Listening for connections", "address", listener.Addr())
	return d.srv.Serve(listener)
}

func (d *Driver) Stop() {
	d.srv.Stop()
}

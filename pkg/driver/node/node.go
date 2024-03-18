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

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/cloud"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/driver/internal"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/driver/mounter"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/util"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/mount-utils"
)

// Supported access modes
const (
	SingleNodeWriter     = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	MultiNodeMultiWriter = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
)

const (
	// default file system type to be used when it is not provided
	defaultFsType = util.FSTypeExt4

	// VolumeOperationAlreadyExists is message fmt returned to CO when there is another in-flight call on the given volumeID
	VolumeOperationAlreadyExists = "An operation with the given volume=%q is already in progress"

	// sbeDeviceVolumeAttachmentLimit refers to the maximum number of volumes that can be attached to an instance on snow.
	sbeDeviceVolumeAttachmentLimit = 10
)

var (
	ValidFSTypes = map[string]struct{}{
		util.FSTypeExt2: {},
		util.FSTypeExt3: {},
		util.FSTypeExt4: {},
		util.FSTypeXfs:  {},
		util.FSTypeNtfs: {},
	}
)

var (
	// nodeCaps represents the capability of node service.
	nodeCaps = []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_EXPAND_VOLUME,
		csi.NodeServiceCapability_RPC_GET_VOLUME_STATS,
	}

	// taintRemovalInitialDelay is the initial delay for node taint removal
	taintRemovalInitialDelay = 1 * time.Second
	// taintRemovalBackoff is the exponential backoff configuration for node taint removal
	taintRemovalBackoff = wait.Backoff{
		Duration: 500 * time.Millisecond,
		Factor:   2,
		Steps:    10, // Max delay = 0.5 * 2^9 = ~4 minutes
	}
)

type NodeOptions struct {
	Region string

	// Add any other node-specific options here
}

const (
	diskPartitionSuffix     = ""
	nvmeDiskPartitionSuffix = "p"
)

// NodeService represents the node service of the CSI driver
type NodeService struct {
	metadata cloud.MetadataService
	mounter  *mount.SafeFormatAndMount
	inFlight *internal.InFlight
	options  *NodeOptions
}

// newNodeService creates a new node service
// it panics if failed to create the service
// NewNodeService creates a new node service
func NewNodeService(options *NodeOptions) (*NodeService, error) {
	klog.V(5).InfoS("[Debug] Retrieving node info from metadata service")
	metadata, err := cloud.NewMetadataService(cloud.DefaultEC2MetadataClient, cloud.DefaultKubernetesAPIClient, options.Region)
	if err != nil {
		return nil, err
	}

	nodeMounter, err := mounter.NewSafeMounter()
	if err != nil {
		return nil, err
	}

	// Remove taint from node to indicate driver startup success
	// This is done at the last possible moment to prevent race conditions or false positive removals
	time.AfterFunc(taintRemovalInitialDelay, func() {
		removeTaintInBackground(cloud.DefaultKubernetesAPIClient, removeNotReadyTaint)
	})

	return &NodeService{
		metadata: metadata,
		mounter:  nodeMounter,
		inFlight: internal.NewInFlight(),
		options:  options,
	}, nil
}

func (d *NodeService) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	klog.V(4).InfoS("NodeStageVolume: called", "args", *req)

	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID not provided")
	}

	target := req.GetStagingTargetPath()
	if len(target) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Staging target not provided")
	}

	volCap := req.GetVolumeCapability()
	if volCap == nil {
		return nil, status.Error(codes.InvalidArgument, "Volume capability not provided")
	}

	if !isValidVolumeCapabilities([]*csi.VolumeCapability{volCap}) {
		return nil, status.Error(codes.InvalidArgument, "Volume capability not supported")
	}
	volumeContext := req.GetVolumeContext()
	if isValidVolumeContext := isValidVolumeContext(volumeContext); !isValidVolumeContext {
		return nil, status.Error(codes.InvalidArgument, "Volume Attribute is not valid")
	}

	// If the access type is block, do nothing for stage
	switch volCap.GetAccessType().(type) {
	case *csi.VolumeCapability_Block:
		return &csi.NodeStageVolumeResponse{}, nil
	}

	mountVolume := volCap.GetMount()
	if mountVolume == nil {
		return nil, status.Error(codes.InvalidArgument, "NodeStageVolume: mount is nil within volume capability")
	}

	fsType := mountVolume.GetFsType()
	if len(fsType) == 0 {
		fsType = defaultFsType
	}

	_, ok := ValidFSTypes[strings.ToLower(fsType)]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "NodeStageVolume: invalid fstype %s", fsType)
	}

	context := req.GetVolumeContext()

	blockSize, err := recheckFormattingOptionParameter(context, util.BlockSizeKey, util.FileSystemConfigs, fsType)
	if err != nil {
		return nil, err
	}
	inodeSize, err := recheckFormattingOptionParameter(context, util.InodeSizeKey, util.FileSystemConfigs, fsType)
	if err != nil {
		return nil, err
	}
	bytesPerInode, err := recheckFormattingOptionParameter(context, util.BytesPerInodeKey, util.FileSystemConfigs, fsType)
	if err != nil {
		return nil, err
	}
	numInodes, err := recheckFormattingOptionParameter(context, util.NumberOfInodesKey, util.FileSystemConfigs, fsType)
	if err != nil {
		return nil, err
	}
	ext4BigAlloc, err := recheckFormattingOptionParameter(context, util.Ext4BigAllocKey, util.FileSystemConfigs, fsType)
	if err != nil {
		return nil, err
	}
	ext4ClusterSize, err := recheckFormattingOptionParameter(context, util.Ext4ClusterSizeKey, util.FileSystemConfigs, fsType)
	if err != nil {
		return nil, err
	}

	mountOptions := collectMountOptions(fsType, mountVolume.MountFlags)

	if ok = d.inFlight.Insert(volumeID); !ok {
		return nil, status.Errorf(codes.Aborted, VolumeOperationAlreadyExists, volumeID)
	}
	defer func() {
		klog.V(4).InfoS("NodeStageVolume: volume operation finished", "volumeID", volumeID)
		d.inFlight.Delete(volumeID)
	}()

	devicePath, ok := req.PublishContext[util.DevicePathKey]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "Device path not provided")
	}

	partition := ""
	if part, ok := volumeContext[util.VolumeAttributePartition]; ok {
		if part != "0" {
			partition = part
		} else {
			klog.InfoS("NodeStageVolume: invalid partition config, will ignore.", "partition", part)
		}
	}

	source, err := findDevicePath(d, devicePath, volumeID, partition)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to find device path %s. %v", devicePath, err)
	}

	klog.V(4).InfoS("NodeStageVolume: find device path", "devicePath", devicePath, "source", source)
	exists, err := PathExists(target)
	if err != nil {
		msg := fmt.Sprintf("failed to check if target %q exists: %v", target, err)
		return nil, status.Error(codes.Internal, msg)
	}
	// When exists is true it means target path was created but device isn't mounted.
	// We don't want to do anything in that case and let the operation proceed.
	// Otherwise we need to create the target directory.
	if !exists {
		// If target path does not exist we need to create the directory where volume will be staged
		klog.V(4).InfoS("NodeStageVolume: creating target dir", "target", target)
		if err = MakeDir(target); err != nil {
			msg := fmt.Sprintf("could not create target dir %q: %v", target, err)
			return nil, status.Error(codes.Internal, msg)
		}
	}

	// Check if a device is mounted in target directory
	device, _, err := GetDeviceNameFromMount(target)
	if err != nil {
		msg := fmt.Sprintf("failed to check if volume is already mounted: %v", err)
		return nil, status.Error(codes.Internal, msg)
	}

	// This operation (NodeStageVolume) MUST be idempotent.
	// If the volume corresponding to the volume_id is already staged to the staging_target_path,
	// and is identical to the specified volume_capability the Plugin MUST reply 0 OK.
	klog.V(4).InfoS("NodeStageVolume: checking if volume is already staged", "device", device, "source", source, "target", target)
	if device == source {
		klog.V(4).InfoS("NodeStageVolume: volume already staged", "volumeID", volumeID)
		return &csi.NodeStageVolumeResponse{}, nil
	}

	// FormatAndMount will format only if needed
	klog.V(4).InfoS("NodeStageVolume: staging volume", "source", source, "volumeID", volumeID, "target", target, "fstype", fsType)
	formatOptions := []string{}
	if len(blockSize) > 0 {
		if fsType == util.FSTypeXfs {
			blockSize = "size=" + blockSize
		}
		formatOptions = append(formatOptions, "-b", blockSize)
	}
	if len(inodeSize) > 0 {
		option := "-I"
		if fsType == util.FSTypeXfs {
			option, inodeSize = "-i", "size="+inodeSize
		}
		formatOptions = append(formatOptions, option, inodeSize)
	}
	if len(bytesPerInode) > 0 {
		formatOptions = append(formatOptions, "-i", bytesPerInode)
	}
	if len(numInodes) > 0 {
		formatOptions = append(formatOptions, "-N", numInodes)
	}
	if ext4BigAlloc == "true" {
		formatOptions = append(formatOptions, "-O", "bigalloc")
	}
	if len(ext4ClusterSize) > 0 {
		formatOptions = append(formatOptions, "-C", ext4ClusterSize)
	}
	err = d.mounter.FormatAndMountSensitiveWithFormatOptions(source, target, fsType, mountOptions, nil, formatOptions)
	if err != nil {
		msg := fmt.Sprintf("could not format %q and mount it at %q: %v", source, target, err)
		return nil, status.Error(codes.Internal, msg)
	}

	needResize, err := NeedResize(source, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not determine if volume %q (%q) need to be resized:  %v", req.GetVolumeId(), source, err)
	}

	if needResize {
		klog.V(2).InfoS("Volume needs resizing", "source", source)
		if _, err := Resize(source, target); err != nil {
			return nil, status.Errorf(codes.Internal, "Could not resize volume %q (%q):  %v", volumeID, source, err)
		}
	}
	klog.V(4).InfoS("NodeStageVolume: successfully staged volume", "source", source, "volumeID", volumeID, "target", target, "fstype", fsType)
	return &csi.NodeStageVolumeResponse{}, nil
}

func (d *NodeService) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	klog.V(4).InfoS("NodeUnstageVolume: called", "args", *req)
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID not provided")
	}

	target := req.GetStagingTargetPath()
	if len(target) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Staging target not provided")
	}

	if ok := d.inFlight.Insert(volumeID); !ok {
		return nil, status.Errorf(codes.Aborted, VolumeOperationAlreadyExists, volumeID)
	}
	defer func() {
		klog.V(4).InfoS("NodeUnStageVolume: volume operation finished", "volumeID", volumeID)
		d.inFlight.Delete(volumeID)
	}()

	// Check if target directory is a mount point. GetDeviceNameFromMount
	// given a mnt point, finds the device from /proc/mounts
	// returns the device name, reference count, and error code
	dev, refCount, err := GetDeviceNameFromMount(target)
	if err != nil {
		msg := fmt.Sprintf("failed to check if target %q is a mount point: %v", target, err)
		return nil, status.Error(codes.Internal, msg)
	}

	// From the spec: If the volume corresponding to the volume_id
	// is not staged to the staging_target_path, the Plugin MUST
	// reply 0 OK.
	if refCount == 0 {
		klog.V(5).InfoS("[Debug] NodeUnstageVolume: target not mounted", "target", target)
		return &csi.NodeUnstageVolumeResponse{}, nil
	}

	if refCount > 1 {
		klog.InfoS("NodeUnstageVolume: found references to device mounted at target path", "refCount", refCount, "device", dev, "target", target)
	}

	klog.V(4).InfoS("NodeUnstageVolume: unmounting", "target", target)
	err = Unstage(target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not unmount target %q: %v", target, err)
	}
	klog.V(4).InfoS("NodeUnStageVolume: successfully unstaged volume", "volumeID", volumeID, "target", target)
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (d *NodeService) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	klog.V(4).InfoS("NodeExpandVolume: called", "args", *req)
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID not provided")
	}
	volumePath := req.GetVolumePath()
	if len(volumePath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "volume path must be provided")
	}

	volumeCapability := req.GetVolumeCapability()
	// VolumeCapability is optional, if specified, use that as source of truth
	if volumeCapability != nil {
		caps := []*csi.VolumeCapability{volumeCapability}
		if !isValidVolumeCapabilities(caps) {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("VolumeCapability is invalid: %v", volumeCapability))
		}

		if blk := volumeCapability.GetBlock(); blk != nil {
			// Noop for Block NodeExpandVolume
			klog.V(4).InfoS("NodeExpandVolume: called. Since it is a block device, ignoring...", "volumeID", volumeID, "volumePath", volumePath)
			return &csi.NodeExpandVolumeResponse{}, nil
		}
	} else {
		// TODO use util.GenericResizeFS
		// VolumeCapability is nil, check if volumePath point to a block device
		isBlock, err := isBlockDevice(volumePath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to determine if volumePath [%v] is a block device: %v", volumePath, err)
		}
		if isBlock {
			// Skip resizing for Block NodeExpandVolume
			bcap, err := getBlockSizeBytes(volumePath)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to get block capacity on path %s: %v", req.VolumePath, err)
			}
			klog.V(4).InfoS("NodeExpandVolume: called, since given volumePath is a block device, ignoring...", "volumeID", volumeID, "volumePath", volumePath)
			return &csi.NodeExpandVolumeResponse{CapacityBytes: bcap}, nil
		}
	}

	deviceName, _, err := GetDeviceNameFromMount(volumePath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get device name from mount %s: %v", volumePath, err)
	}

	devicePath, err := findDevicePath(d, deviceName, volumeID, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find device path for device name %s for mount %s: %v", deviceName, req.GetVolumePath(), err)
	}

	r, err := NewResizeFs()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error attempting to create new ResizeFs:  %v", err)
	}

	// TODO: lock per volume ID to have some idempotency
	if _, err = r.Resize(devicePath, volumePath); err != nil {
		return nil, status.Errorf(codes.Internal, "Could not resize volume %q (%q):  %v", volumeID, devicePath, err)
	}

	bcap, err := getBlockSizeBytes(devicePath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get block capacity on path %s: %v", req.VolumePath, err)
	}
	return &csi.NodeExpandVolumeResponse{CapacityBytes: bcap}, nil
}

func getBlockSizeBytes(devicePath string) (int64, error) {
	cmd := d.mounter.(*NodeMounter).Exec.Command("blockdev", "--getsize64", devicePath)
	output, err := cmd.Output()
	if err != nil {
		return -1, fmt.Errorf("error when getting size of block volume at path %s: output: %s, err: %w", devicePath, string(output), err)
	}
	strOut := strings.TrimSpace(string(output))
	gotSizeBytes, err := strconv.ParseInt(strOut, 10, 64)
	if err != nil {
		return -1, fmt.Errorf("failed to parse size %s as int", strOut)
	}
	return gotSizeBytes, nil
}

func (d *NodeService) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	klog.V(4).InfoS("NodePublishVolume: called", "args", *req)
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID not provided")
	}

	source := req.GetStagingTargetPath()
	if len(source) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Staging target not provided")
	}

	target := req.GetTargetPath()
	if len(target) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path not provided")
	}

	volCap := req.GetVolumeCapability()
	if volCap == nil {
		return nil, status.Error(codes.InvalidArgument, "Volume capability not provided")
	}

	if !isValidVolumeCapabilities([]*csi.VolumeCapability{volCap}) {
		return nil, status.Error(codes.InvalidArgument, "Volume capability not supported")
	}

	if ok := d.inFlight.Insert(volumeID); !ok {
		return nil, status.Errorf(codes.Aborted, VolumeOperationAlreadyExists, volumeID)
	}
	defer func() {
		klog.V(4).InfoS("NodePublishVolume: volume operation finished", "volumeId", volumeID)
		d.inFlight.Delete(volumeID)
	}()

	mountOptions := []string{"bind"}
	if req.GetReadonly() {
		mountOptions = append(mountOptions, "ro")
	}

	switch mode := volCap.GetAccessType().(type) {
	case *csi.VolumeCapability_Block:
		if err := d.nodePublishVolumeForBlock(req, mountOptions); err != nil {
			return nil, err
		}
	case *csi.VolumeCapability_Mount:
		if err := d.nodePublishVolumeForFileSystem(req, mountOptions, mode); err != nil {
			return nil, err
		}
	}

	return &csi.NodePublishVolumeResponse{}, nil
}

func (d *NodeService) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	klog.V(4).InfoS("NodeUnpublishVolume: called", "args", *req)
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID not provided")
	}

	target := req.GetTargetPath()
	if len(target) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path not provided")
	}
	if ok := d.inFlight.Insert(volumeID); !ok {
		return nil, status.Errorf(codes.Aborted, VolumeOperationAlreadyExists, volumeID)
	}
	defer func() {
		klog.V(4).InfoS("NodeUnPublishVolume: volume operation finished", "volumeId", volumeID)
		d.inFlight.Delete(volumeID)
	}()

	klog.V(4).InfoS("NodeUnpublishVolume: unmounting", "target", target)
	err := d.mounter.Unpublish(target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not unmount %q: %v", target, err)
	}

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func isBlockDevice(fullPath string) (bool, error) {
	var st unix.Stat_t
	err := unix.Stat(fullPath, &st)
	if err != nil {
		return false, err
	}

	return (st.Mode & unix.S_IFMT) == unix.S_IFBLK, nil
}

func (d *NodeService) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	klog.V(4).InfoS("NodeGetVolumeStats: called", "args", *req)
	if len(req.VolumeId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "NodeGetVolumeStats volume ID was empty")
	}
	if len(req.VolumePath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "NodeGetVolumeStats volume path was empty")
	}

	exists, err := d.mounter.PathExists(req.VolumePath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unknown error when stat on %s: %v", req.VolumePath, err)
	}
	if !exists {
		return nil, status.Errorf(codes.NotFound, "path %s does not exist", req.VolumePath)
	}

	isBlock, err := isBlockDevice(req.VolumePath)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to determine whether %s is block device: %v", req.VolumePath, err)
	}
	if isBlock {
		bcap, blockErr := getBlockSizeBytes(req.VolumePath)
		if blockErr != nil {
			return nil, status.Errorf(codes.Internal, "failed to get block capacity on path %s: %v", req.VolumePath, err)
		}
		return &csi.NodeGetVolumeStatsResponse{
			Usage: []*csi.VolumeUsage{
				{
					Unit:  csi.VolumeUsage_BYTES,
					Total: bcap,
				},
			},
		}, nil
	}

	metricsProvider := volume.NewMetricsStatFS(req.VolumePath)

	metrics, err := metricsProvider.GetMetrics()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get fs info on path %s: %v", req.VolumePath, err)
	}

	return &csi.NodeGetVolumeStatsResponse{
		Usage: []*csi.VolumeUsage{
			{
				Unit:      csi.VolumeUsage_BYTES,
				Available: metrics.Available.AsDec().UnscaledBig().Int64(),
				Total:     metrics.Capacity.AsDec().UnscaledBig().Int64(),
				Used:      metrics.Used.AsDec().UnscaledBig().Int64(),
			},
			{
				Unit:      csi.VolumeUsage_INODES,
				Available: metrics.InodesFree.AsDec().UnscaledBig().Int64(),
				Total:     metrics.Inodes.AsDec().UnscaledBig().Int64(),
				Used:      metrics.InodesUsed.AsDec().UnscaledBig().Int64(),
			},
		},
	}, nil

}

func (d *NodeService) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	klog.V(4).InfoS("NodeGetCapabilities: called", "args", *req)
	var caps []*csi.NodeServiceCapability
	for _, cap := range nodeCaps {
		c := &csi.NodeServiceCapability{
			Type: &csi.NodeServiceCapability_Rpc{
				Rpc: &csi.NodeServiceCapability_RPC{
					Type: cap,
				},
			},
		}
		caps = append(caps, c)
	}
	return &csi.NodeGetCapabilitiesResponse{Capabilities: caps}, nil
}

func (d *NodeService) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	klog.V(4).InfoS("NodeGetInfo: called", "args", *req)

	zone := d.metadata.GetAvailabilityZone()

	segments := map[string]string{
		util.TopologyKey:          zone,
		util.WellKnownTopologyKey: zone,
	}

	outpostArn := d.metadata.GetOutpostArn()

	// to my surprise ARN's string representation is not empty for empty ARN
	if len(outpostArn.Resource) > 0 {
		segments[util.AwsRegionKey] = outpostArn.Region
		segments[util.AwsPartitionKey] = outpostArn.Partition
		segments[util.AwsAccountIDKey] = outpostArn.AccountID
		segments[util.AwsOutpostIDKey] = outpostArn.Resource
	}

	topology := &csi.Topology{Segments: segments}

	return &csi.NodeGetInfoResponse{
		NodeId:             d.metadata.GetInstanceID(),
		MaxVolumesPerNode:  d.getVolumesLimit(),
		AccessibleTopology: topology,
	}, nil
}

func appendPartition(devicePath, partition string) string {
	if partition == "" {
		return devicePath
	}

	if strings.HasPrefix(devicePath, "/dev/nvme") {
		return devicePath + nvmeDiskPartitionSuffix + partition
	}

	return devicePath + diskPartitionSuffix + partition
}

func (d *NodeService) nodePublishVolumeForBlock(req *csi.NodePublishVolumeRequest, mountOptions []string) error {
	target := req.GetTargetPath()
	volumeID := req.GetVolumeId()
	volumeContext := req.GetVolumeContext()

	devicePath, exists := req.PublishContext[util.DevicePathKey]
	if !exists {
		return status.Error(codes.InvalidArgument, "Device path not provided")
	}
	if isValidVolumeContext := isValidVolumeContext(volumeContext); !isValidVolumeContext {
		return status.Error(codes.InvalidArgument, "Volume Attribute is invalid")
	}

	partition := ""
	if part, ok := req.GetVolumeContext()[util.VolumeAttributePartition]; ok {
		if part != "0" {
			partition = part
		} else {
			klog.InfoS("NodePublishVolume: invalid partition config, will ignore.", "partition", part)
		}
	}

	source, err := findDevicePath(d, devicePath, volumeID, partition)
	if err != nil {
		return status.Errorf(codes.Internal, "Failed to find device path %s. %v", devicePath, err)
	}

	klog.V(4).InfoS("NodePublishVolume [block]: find device path", "devicePath", devicePath, "source", source)

	globalMountPath := filepath.Dir(target)

	// create the global mount path if it is missing
	// Path in the form of /var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/publish/{volumeName}
	exists, err = d.mounter.PathExists(globalMountPath)
	if err != nil {
		return status.Errorf(codes.Internal, "Could not check if path exists %q: %v", globalMountPath, err)
	}

	if !exists {
		if err = d.mounter.MakeDir(globalMountPath); err != nil {
			return status.Errorf(codes.Internal, "Could not create dir %q: %v", globalMountPath, err)
		}
	}

	// Create the mount point as a file since bind mount device node requires it to be a file
	klog.V(4).InfoS("NodePublishVolume [block]: making target file", "target", target)
	if err = d.mounter.MakeFile(target); err != nil {
		if removeErr := os.Remove(target); removeErr != nil {
			return status.Errorf(codes.Internal, "Could not remove mount target %q: %v", target, removeErr)
		}
		return status.Errorf(codes.Internal, "Could not create file %q: %v", target, err)
	}

	//Checking if the target file is already mounted with a device.
	mounted, err := d.isMounted(source, target)
	if err != nil {
		return status.Errorf(codes.Internal, "Could not check if %q is mounted: %v", target, err)
	}

	if !mounted {
		klog.V(4).InfoS("NodePublishVolume [block]: mounting", "source", source, "target", target)
		if err := d.mounter.Mount(source, target, "", mountOptions); err != nil {
			if removeErr := os.Remove(target); removeErr != nil {
				return status.Errorf(codes.Internal, "Could not remove mount target %q: %v", target, removeErr)
			}
			return status.Errorf(codes.Internal, "Could not mount %q at %q: %v", source, target, err)
		}
	} else {
		klog.V(4).InfoS("NodePublishVolume [block]: Target path is already mounted", "target", target)
	}

	return nil
}

func findDevicePath(h *NodeService, devicePath, volumeID, partition string) (string, error) {
	strippedVolumeName := strings.Replace(volumeID, "-", "", -1)
	canonicalDevicePath := ""

	// If the given path exists, the device MAY be nvme. Further, it MAY be a
	// symlink to the nvme device path like:
	// | $ stat /dev/xvdba
	// | File: ‘/dev/xvdba’ -> ‘nvme1n1’
	// Since these are maybes, not guarantees, the search for the nvme device
	// path below must happen and must rely on volume ID
	exists, err := h.mounter.PathExists(devicePath)
	if err != nil {
		return "", fmt.Errorf("failed to check if path %q exists: %w", devicePath, err)
	}

	if exists {
		stat, lstatErr := os.Lstat(devicePath)
		if lstatErr != nil {
			return "", fmt.Errorf("failed to lstat %q: %w", devicePath, err)
		}

		if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
			canonicalDevicePath, err = filepath.EvalSymlinks(devicePath)
			if err != nil {
				return "", fmt.Errorf("failed to evaluate symlink %q: %w", devicePath, err)
			}
		} else {
			canonicalDevicePath = devicePath
		}

		klog.V(5).InfoS("[Debug] The canonical device path was resolved", "devicePath", devicePath, "cacanonicalDevicePath", canonicalDevicePath)
		if err = verifyVolumeSerialMatch(canonicalDevicePath, strippedVolumeName, execRunner); err != nil {
			return "", err
		}
		return appendPartition(canonicalDevicePath, partition), nil
	}

	klog.V(5).InfoS("[Debug] Falling back to nvme volume ID lookup", "devicePath", devicePath)

	// AWS recommends identifying devices by volume ID
	// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html),
	// so find the nvme device path using volume ID. This is the magic name on
	// which AWS presents NVME devices under /dev/disk/by-id/. For example,
	// vol-0fab1d5e3f72a5e23 creates a symlink at
	// /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol0fab1d5e3f72a5e23
	nvmeName := "nvme-Amazon_Elastic_Block_Store_" + strippedVolumeName

	nvmeDevicePath, err := findNvmeVolume(d.deviceIdentifier, nvmeName)

	if err == nil {
		klog.V(5).InfoS("[Debug] successfully resolved", "nvmeName", nvmeName, "nvmeDevicePath", nvmeDevicePath)
		canonicalDevicePath = nvmeDevicePath
		if err = verifyVolumeSerialMatch(canonicalDevicePath, strippedVolumeName, execRunner); err != nil {
			return "", err
		}
		return appendPartition(canonicalDevicePath, partition), nil
	} else {
		klog.V(5).InfoS("[Debug] error searching for nvme path", "nvmeName", nvmeName, "err", err)
	}

	if util.IsSBE(d.metadata.GetRegion()) {
		klog.V(5).InfoS("[Debug] Falling back to snow volume lookup", "devicePath", devicePath)
		// Snow completely ignores the requested device path and mounts volumes starting at /dev/vda .. /dev/vdb .. etc
		// Morph the device path to the snow form by chopping off the last letter and prefixing with /dev/vd
		// VMs on snow devices are currently limited to 10 block devices each - if that ever exceeds 26 this will need
		// to be adapted
		canonicalDevicePath = "/dev/vd" + devicePath[len(devicePath)-1:]
	}

	if canonicalDevicePath == "" {
		return "", errNoDevicePathFound(devicePath, volumeID)
	}

	canonicalDevicePath = appendPartition(canonicalDevicePath, partition)
	return canonicalDevicePath, nil
}

// isMounted checks if target is mounted. It does NOT return an error if target
// doesn't exist.
func (d *NodeService) isMounted(_ string, target string) (bool, error) {
	/*
		Checking if it's a mount point using IsLikelyNotMountPoint. There are three different return values,
		1. true, err when the directory does not exist or corrupted.
		2. false, nil when the path is already mounted with a device.
		3. true, nil when the path is not mounted with any device.
	*/
	notMnt, err := d.mounter.IsLikelyNotMountPoint(target)
	if err != nil && !os.IsNotExist(err) {
		//Checking if the path exists and error is related to Corrupted Mount, in that case, the system could unmount and mount.
		_, pathErr := d.mounter.PathExists(target)
		if pathErr != nil && d.mounter.IsCorruptedMnt(pathErr) {
			klog.V(4).InfoS("NodePublishVolume: Target path is a corrupted mount. Trying to unmount.", "target", target)
			if mntErr := d.mounter.Unpublish(target); mntErr != nil {
				return false, status.Errorf(codes.Internal, "Unable to unmount the target %q : %v", target, mntErr)
			}
			//After successful unmount, the device is ready to be mounted.
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "Could not check if %q is a mount point: %v, %v", target, err, pathErr)
	}

	// Do not return os.IsNotExist error. Other errors were handled above.  The
	// Existence of the target should be checked by the caller explicitly and
	// independently because sometimes prior to mount it is expected not to exist
	// (in Windows, the target must NOT exist before a symlink is created at it)
	// and in others it is an error (in Linux, the target mount directory must
	// exist before mount is called on it)
	if err != nil && os.IsNotExist(err) {
		klog.V(5).InfoS("[Debug] NodePublishVolume: Target path does not exist", "target", target)
		return false, nil
	}

	if !notMnt {
		klog.V(4).InfoS("NodePublishVolume: Target path is already mounted", "target", target)
	}

	return !notMnt, nil
}

func (d *NodeService) nodePublishVolumeForFileSystem(req *csi.NodePublishVolumeRequest, mountOptions []string, mode *csi.VolumeCapability_Mount) error {
	target := req.GetTargetPath()
	source := req.GetStagingTargetPath()
	if m := mode.Mount; m != nil {
		for _, f := range m.MountFlags {
			if !hasMountOption(mountOptions, f) {
				mountOptions = append(mountOptions, f)
			}
		}
	}

	if err := d.preparePublishTarget(target); err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}

	//Checking if the target directory is already mounted with a device.
	mounted, err := d.isMounted(source, target)
	if err != nil {
		return status.Errorf(codes.Internal, "Could not check if %q is mounted: %v", target, err)
	}

	if !mounted {
		fsType := mode.Mount.GetFsType()
		if len(fsType) == 0 {
			fsType = defaultFsType
		}

		_, ok := ValidFSTypes[strings.ToLower(fsType)]
		if !ok {
			return status.Errorf(codes.InvalidArgument, "NodePublishVolume: invalid fstype %s", fsType)
		}

		mountOptions = collectMountOptions(fsType, mountOptions)
		klog.V(4).InfoS("NodePublishVolume: mounting", "source", source, "target", target, "mountOptions", mountOptions, "fsType", fsType)
		if err := d.mounter.Mount(source, target, fsType, mountOptions); err != nil {
			return status.Errorf(codes.Internal, "Could not mount %q at %q: %v", source, target, err)
		}
	}

	return nil
}

// getVolumesLimit returns the limit of volumes that the node supports
func (d *NodeService) getVolumesLimit() int64 {
	if d.options.volumeAttachLimit >= 0 {
		return d.options.volumeAttachLimit
	}

	if util.IsSBE(d.metadata.GetRegion()) {
		return sbeDeviceVolumeAttachmentLimit
	}

	instanceType := d.metadata.GetInstanceType()

	isNitro := cloud.IsNitroInstanceType(instanceType)
	availableAttachments := cloud.GetMaxAttachments(isNitro)

	reservedVolumeAttachments := d.options.reservedVolumeAttachments
	if reservedVolumeAttachments == -1 {
		reservedVolumeAttachments = d.metadata.GetNumBlockDeviceMappings() + 1 // +1 for the root device
	}

	dedicatedLimit := cloud.GetDedicatedLimitForInstanceType(instanceType)
	maxEBSAttachments, ok := cloud.GetEBSLimitForInstanceType(instanceType)
	if ok {
		availableAttachments = min(maxEBSAttachments, availableAttachments)
	}
	// For special dedicated limit instance types, the limit is only for EBS volumes
	// For (all other) Nitro instances, attachments are shared between EBS volumes, ENIs and NVMe instance stores
	if dedicatedLimit != 0 {
		availableAttachments = dedicatedLimit
	} else if isNitro {
		enis := d.metadata.GetNumAttachedENIs()
		nvmeInstanceStoreVolumes := cloud.GetNVMeInstanceStoreVolumesForInstanceType(instanceType)
		availableAttachments = availableAttachments - enis - nvmeInstanceStoreVolumes
	}
	availableAttachments = availableAttachments - reservedVolumeAttachments
	if availableAttachments <= 0 {
		availableAttachments = 1
	}

	return int64(availableAttachments)
}

func min(x, y int) int {
	if x <= y {
		return x
	}
	return y
}

// hasMountOption returns a boolean indicating whether the given
// slice already contains a mount option. This is used to prevent
// passing duplicate option to the mount command.
func hasMountOption(options []string, opt string) bool {
	for _, o := range options {
		if o == opt {
			return true
		}
	}
	return false
}

// collectMountOptions returns array of mount options from
// VolumeCapability_MountVolume and special mount options for
// given filesystem.
func collectMountOptions(fsType string, mntFlags []string) []string {
	var options []string
	for _, opt := range mntFlags {
		if !hasMountOption(options, opt) {
			options = append(options, opt)
		}
	}

	// By default, xfs does not allow mounting of two volumes with the same filesystem uuid.
	// Force ignore this uuid to be able to mount volume + its clone / restored snapshot on the same node.
	if fsType == util.FSTypeXfs {
		if !hasMountOption(options, "nouuid") {
			options = append(options, "nouuid")
		}
	}
	return options
}

// Struct for JSON patch operations
type JSONPatch struct {
	OP    string      `json:"op,omitempty"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value"`
}

// removeTaintInBackground is a goroutine that retries removeNotReadyTaint with exponential backoff
func removeTaintInBackground(k8sClient cloud.KubernetesAPIClient, removalFunc func(cloud.KubernetesAPIClient) error) {
	backoffErr := wait.ExponentialBackoff(taintRemovalBackoff, func() (bool, error) {
		err := removalFunc(k8sClient)
		if err != nil {
			klog.ErrorS(err, "Unexpected failure when attempting to remove node taint(s)")
			return false, nil
		}
		return true, nil
	})

	if backoffErr != nil {
		klog.ErrorS(backoffErr, "Retries exhausted, giving up attempting to remove node taint(s)")
	}
}

// removeNotReadyTaint removes the taint ebs.csi.aws.com/agent-not-ready from the local node
// This taint can be optionally applied by users to prevent startup race conditions such as
// https://github.com/kubernetes/kubernetes/issues/95911
func removeNotReadyTaint(k8sClient cloud.KubernetesAPIClient) error {
	nodeName := os.Getenv("CSI_NODE_NAME")
	if nodeName == "" {
		klog.V(4).InfoS("CSI_NODE_NAME missing, skipping taint removal")
		return nil
	}

	clientset, err := k8sClient()
	if err != nil {
		klog.V(4).InfoS("Failed to setup k8s client")
		return nil //lint:ignore nilerr If there are no k8s credentials, treat that as a soft failure
	}

	node, err := clientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	err = checkAllocatable(clientset, nodeName)
	if err != nil {
		return err
	}

	var taintsToKeep []corev1.Taint
	for _, taint := range node.Spec.Taints {
		if taint.Key != util.AgentNotReadyNodeTaintKey {
			taintsToKeep = append(taintsToKeep, taint)
		} else {
			klog.V(4).InfoS("Queued taint for removal", "key", taint.Key, "effect", taint.Effect)
		}
	}

	if len(taintsToKeep) == len(node.Spec.Taints) {
		klog.V(4).InfoS("No taints to remove on node, skipping taint removal")
		return nil
	}

	patchRemoveTaints := []JSONPatch{
		{
			OP:    "test",
			Path:  "/spec/taints",
			Value: node.Spec.Taints,
		},
		{
			OP:    "replace",
			Path:  "/spec/taints",
			Value: taintsToKeep,
		},
	}

	patch, err := json.Marshal(patchRemoveTaints)
	if err != nil {
		return err
	}

	_, err = clientset.CoreV1().Nodes().Patch(context.Background(), nodeName, k8stypes.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	klog.InfoS("Removed taint(s) from local node", "node", nodeName)
	return nil
}

func checkAllocatable(clientset kubernetes.Interface, nodeName string) error {
	csiNode, err := clientset.StorageV1().CSINodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("isAllocatableSet: failed to get CSINode for %s: %w", nodeName, err)
	}

	for _, driver := range csiNode.Spec.Drivers {
		if driver.Name == util.DriverName {
			if driver.Allocatable != nil && driver.Allocatable.Count != nil {
				klog.InfoS("CSINode Allocatable value is set", "nodeName", nodeName, "count", *driver.Allocatable.Count)
				return nil
			}
			return fmt.Errorf("isAllocatableSet: allocatable value not set for driver on node %s", nodeName)
		}
	}

	return fmt.Errorf("isAllocatableSet: driver not found on node %s", nodeName)
}

func recheckFormattingOptionParameter(context map[string]string, key string, fsConfigs map[string]util.FileSystemConfig, fsType string) (value string, err error) {
	v, ok := context[key]
	if ok {
		// This check is already performed on the controller side
		// However, because it is potentially security-sensitive, we redo it here to be safe
		if isAlphanumeric := util.StringIsAlphanumeric(value); !isAlphanumeric {
			return "", status.Errorf(codes.InvalidArgument, "Invalid %s (aborting!): %v", key, err)
		}

		// In the case that the default fstype does not support custom sizes we could
		// be using an invalid fstype, so recheck that here
		if supported := fsConfigs[strings.ToLower(fsType)].IsParameterSupported(key); !supported {
			return "", status.Errorf(codes.InvalidArgument, "Cannot use %s with fstype %s", key, fsType)
		}
	}
	return v, nil
}

func isValidVolumeCapabilities(v []*csi.VolumeCapability) bool {
	for _, c := range v {
		if !isValidCapability(c) {
			return false
		}
	}
	return true
}

func isValidCapability(c *csi.VolumeCapability) bool {
	accessMode := c.GetAccessMode().GetMode()

	//nolint:exhaustive
	switch accessMode {
	case SingleNodeWriter:
		return true

	case MultiNodeMultiWriter:
		if isBlock(c) {
			return true
		} else {
			klog.InfoS("isValidCapability: access mode is only supported for block devices", "accessMode", accessMode)
			return false
		}

	default:
		klog.InfoS("isValidCapability: access mode is not supported", "accessMode", accessMode)
		return false
	}
}

func isBlock(cap *csi.VolumeCapability) bool {
	_, isBlock := cap.GetAccessType().(*csi.VolumeCapability_Block)
	return isBlock
}

func isValidVolumeContext(volContext map[string]string) bool {
	//There could be multiple volume attributes in the volumeContext map
	//Validate here case by case
	if partition, ok := volContext[util.VolumeAttributePartition]; ok {
		partitionInt, err := strconv.ParseInt(partition, 10, 64)
		if err != nil {
			klog.ErrorS(err, "failed to parse partition as int", "partition", partition)
			return false
		}
		if partitionInt < 0 {
			klog.ErrorS(err, "invalid partition config", "partition", partition)
			return false
		}
	}
	return true
}

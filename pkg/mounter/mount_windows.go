//go:build windows
// +build windows

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

package mounter

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	disk "github.com/kubernetes-csi/csi-proxy/client/api/disk/v1"
	fs "github.com/kubernetes-csi/csi-proxy/client/api/filesystem/v1"
	volume "github.com/kubernetes-csi/csi-proxy/client/api/volume/v1"
	diskclient "github.com/kubernetes-csi/csi-proxy/client/groups/disk/v1"
	fsclient "github.com/kubernetes-csi/csi-proxy/client/groups/filesystem/v1"
	volumeclient "github.com/kubernetes-csi/csi-proxy/client/groups/volume/v1"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/util"

	"k8s.io/klog/v2"
	mountutils "k8s.io/mount-utils"
	utilexec "k8s.io/utils/exec"
)

type CSIProxyMounter struct {
	FsClient     *fsclient.Client
	DiskClient   *diskclient.Client
	VolumeClient *volumeclient.Client
}

// NewSafeMounter returns a new instance of SafeFormatAndMount.
func NewSafeMounter() (*mountutils.SafeFormatAndMount, error) {
	fsClient, err := fsclient.NewClient()
	if err != nil {
		return nil, err
	}
	diskClient, err := diskclient.NewClient()
	if err != nil {
		return nil, err
	}
	volumeClient, err := volumeclient.NewClient()
	if err != nil {
		return nil, err
	}
	return &mountutils.SafeFormatAndMount{
		Interface: &CSIProxyMounter{
			FsClient:     fsClient,
			DiskClient:   diskClient,
			VolumeClient: volumeClient,
		},
		Exec: utilexec.New(),
	}, nil
}

// Mount mounts the volume.
func (mounter *CSIProxyMounter) Mount(source string, target string, fstype string, options []string) error {
	// Mount is called after the format is done.
	// TODO: Confirm that fstype is empty.
	linkRequest := &fs.CreateSymlinkRequest{
		SourcePath: util.NormalizeWindowsPath(source),
		TargetPath: util.NormalizeWindowsPath(target),
	}
	_, err := mounter.FsClient.CreateSymlink(context.Background(), linkRequest)
	if err != nil {
		return err
	}
	return nil
}

// Unmount unmounts the volume.
func (mounter *CSIProxyMounter) Unmount(target string) error {
	// Find the volume id
	getVolumeIdRequest := &volume.GetVolumeIDFromTargetPathRequest{
		TargetPath: util.NormalizeWindowsPath(target),
	}
	volumeIdResponse, err := mounter.VolumeClient.GetVolumeIDFromTargetPath(context.Background(), getVolumeIdRequest)
	if err != nil {
		return err
	}

	// Call UnmountVolume CSI proxy function which flushes data cache to disk and removes the global staging path
	unmountVolumeRequest := &volume.UnmountVolumeRequest{
		VolumeId:   volumeIdResponse.VolumeId,
		TargetPath: util.NormalizeWindowsPath(target),
	}
	_, err = mounter.VolumeClient.UnmountVolume(context.Background(), unmountVolumeRequest)
	if err != nil {
		return err
	}

	// Cleanup stage path
	err = mounter.Rmdir(target)
	if err != nil {
		return err
	}

	// Get disk number
	getDiskNumberRequest := &volume.GetDiskNumberFromVolumeIDRequest{
		VolumeId: volumeIdResponse.VolumeId,
	}
	getDiskNumberResponse, err := mounter.VolumeClient.GetDiskNumberFromVolumeID(context.Background(), getDiskNumberRequest)
	if err != nil {
		return err
	}

	// Offline the disk
	setDiskStateRequest := &disk.SetDiskStateRequest{
		DiskNumber: getDiskNumberResponse.DiskNumber,
		IsOnline:   false,
	}
	_, err = mounter.DiskClient.SetDiskState(context.Background(), setDiskStateRequest)
	if err != nil {
		return err
	}
	klog.V(4).InfoS("Successfully unmounted volume", "diskNumber", getDiskNumberResponse.DiskNumber, "volumeId", volumeIdResponse.VolumeId, "target", target)
	return nil
}

// Rmdir removes the directory.
func (mounter *CSIProxyMounter) Rmdir(path string) error {
	rmdirRequest := &fs.RmdirRequest{
		Path:  util.NormalizeWindowsPath(path),
		Force: true,
	}
	_, err := mounter.FsClient.Rmdir(context.Background(), rmdirRequest)
	if err != nil {
		return err
	}
	return nil
}

// ExistsPath checks if a path exists.
func (mounter *CSIProxyMounter) ExistsPath(path string) (bool, error) {
	isExistsResponse, err := mounter.FsClient.PathExists(context.Background(),
		&fs.PathExistsRequest{
			Path: util.NormalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return isExistsResponse.Exists, err
}

// IsLikelyNotMountPoint checks if the path is a mount point.
func (mounter *CSIProxyMounter) IsLikelyNotMountPoint(path string) (bool, error) {
	isExists, err := mounter.ExistsPath(path)
	if err != nil {
		return false, err
	}
	if !isExists {
		return true, os.ErrNotExist
	}

	response, err := mounter.FsClient.IsSymlink(context.Background(),
		&fs.IsSymlinkRequest{
			Path: util.NormalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return !response.IsSymlink, nil
}

// GetDeviceSize returns the size of the disk in bytes
func (mounter *CSIProxyMounter) GetDeviceSize(devicePath string) (int64, error) {
	diskNumber, err := strconv.Atoi(devicePath)
	if err != nil {
		return -1, err
	}

	//Get size of the disk
	getDiskStatsRequest := &disk.GetDiskStatsRequest{
		DiskNumber: uint32(diskNumber),
	}
	resp, err := mounter.DiskClient.GetDiskStats(context.Background(), getDiskStatsRequest)
	if err != nil {
		return -1, err
	}

	return resp.TotalBytes, nil
}

// GetVolumeSizeInBytes returns the size of the volume in bytes
func (mounter *CSIProxyMounter) GetVolumeSizeInBytes(deviceMountPath string) (int64, error) {
	// Find the volume id
	getVolumeIdRequest := &volume.GetVolumeIDFromTargetPathRequest{
		TargetPath: util.NormalizeWindowsPath(deviceMountPath),
	}
	volumeIdResponse, err := mounter.VolumeClient.GetVolumeIDFromTargetPath(context.Background(), getVolumeIdRequest)
	if err != nil {
		return -1, err
	}
	volumeId := volumeIdResponse.GetVolumeId()

	// Get size of the volume
	getVolumeStatsRequest := &volume.GetVolumeStatsRequest{
		VolumeId: volumeId,
	}
	resp, err := mounter.VolumeClient.GetVolumeStats(context.Background(), getVolumeStatsRequest)
	if err != nil {
		return -1, err
	}

	return resp.TotalBytes, nil
}

// FormatAndMountSensitiveWithFormatOptions formats and mounts the volume.
func (mounter *CSIProxyMounter) FormatAndMountSensitiveWithFormatOptions(source string, target string, fstype string, options []string, sensitiveOptions []string, formatOptions []string) error {
	// sensitiveOptions and formatOptions are not supported on Windows because
	// the CSI proxy does not provide a way to pass them.
	if len(sensitiveOptions) != 0 {
		return fmt.Errorf("WindowsMounter does not support sensitiveOptions")
	}
	if len(formatOptions) != 0 {
		return fmt.Errorf("WindowsMounter does not support formatOptions")
	}

	diskNumber, err := strconv.Atoi(source)
	if err != nil {
		return err
	}

	// Call PartitionDisk CSI proxy call to partition the disk and return the volume id
	partitionDiskRequest := &disk.PartitionDiskRequest{
		DiskNumber: uint32(diskNumber),
	}
	_, err = mounter.DiskClient.PartitionDisk(context.Background(), partitionDiskRequest)
	if err != nil {
		return err
	}

	// Ensure the disk is online before mounting.
	setDiskStateRequest := &disk.SetDiskStateRequest{
		DiskNumber: uint32(diskNumber),
		IsOnline:   true,
	}
	_, err = mounter.DiskClient.SetDiskState(context.Background(), setDiskStateRequest)
	if err != nil {
		return err
	}

	// List the volumes on the given disk.
	volumeIDsRequest := &volume.ListVolumesOnDiskRequest{
		DiskNumber: uint32(diskNumber),
	}
	volumeIDResponse, err := mounter.VolumeClient.ListVolumesOnDisk(context.Background(), volumeIDsRequest)
	if err != nil {
		return err
	}

	// TODO: consider partitions and choose the right partition.
	// For now just choose the first volume.
	volumeID := volumeIDResponse.VolumeIds[0]

	// Check if the volume is formatted.
	isVolumeFormattedRequest := &volume.IsVolumeFormattedRequest{
		VolumeId: volumeID,
	}
	isVolumeFormattedResponse, err := mounter.VolumeClient.IsVolumeFormatted(context.Background(), isVolumeFormattedRequest)
	if err != nil {
		return err
	}

	// If the volume is not formatted, then format it, else proceed to mount.
	if !isVolumeFormattedResponse.Formatted {
		formatVolumeRequest := &volume.FormatVolumeRequest{
			VolumeId: volumeID,
			// TODO: Accept the filesystem type and format options
		}
		_, err = mounter.VolumeClient.FormatVolume(context.Background(), formatVolumeRequest)
		if err != nil {
			return err
		}
	}

	// Mount the volume by calling the CSI proxy call.
	mountVolumeRequest := &volume.MountVolumeRequest{
		VolumeId:   volumeID,
		TargetPath: util.NormalizeWindowsPath(target),
	}
	_, err = mounter.VolumeClient.MountVolume(context.Background(), mountVolumeRequest)
	if err != nil {
		return err
	}
	return nil
}

func (mounter *CSIProxyMounter) List() ([]mountutils.MountPoint, error) {
	return []mountutils.MountPoint{}, fmt.Errorf("List not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) CanSafelySkipMountPointCheck() bool {
	return false
}

func (mounter *CSIProxyMounter) GetMountRefs(string) ([]string, error) {
	return nil, fmt.Errorf("GetMountRefs not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) IsMountPoint(string) (bool, error) {
	return false, fmt.Errorf("GetMountRefs not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) MountSensitive(string, string, string, []string, []string) error {
	return fmt.Errorf("MountSensitive not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) MountSensitiveWithoutSystemd(string, string, string, []string, []string) error {
	return fmt.Errorf("MountSensitiveWithoutSystemd not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) MountSensitiveWithoutSystemdWithMountFlags(string, string, string, []string, []string, []string) error {
	return fmt.Errorf("MountSensitiveWithoutSystemdWithMountFlags not implemented for CSIProxyMounter")
}

// GetDeviceNameFromMount returns the device name and partition number for the given mount path.
func (mounter *NodeMounter) GetDeviceNameFromMount(mountPath string) (string, int, error) {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return getDeviceNameFromMountV1(csiProxyMounter, mountPath)
	case *CSIProxyMounterV2:
		return getDeviceNameFromMountV2(csiProxyMounter, mountPath)
	default:
		return "", 0, fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func getDeviceNameFromMountV1(mounter mountutils.Interface, mountPath string) (string, int, error) {
	csiProxyMounter, ok := mounter.(*CSIProxyMounter)
	if !ok {
		return "", 0, fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}

	req := &volume.GetVolumeIDFromTargetPathRequest{TargetPath: util.NormalizeWindowsPath(mountPath)}
	resp, err := csiProxyMounter.VolumeClient.GetVolumeIDFromTargetPath(context.Background(), req)
	if err != nil {
		return "", 0, err
	}
	// Get disk number
	getDiskNumberRequest := &volume.GetDiskNumberFromVolumeIDRequest{
		VolumeId: resp.VolumeId,
	}
	getDiskNumberResponse, err := csiProxyMounter.VolumeClient.GetDiskNumberFromVolumeID(context.Background(), getDiskNumberRequest)
	if err != nil {
		return "", 0, err
	}
	klog.V(4).InfoS("GetDeviceNameFromMount called", "diskNumber", getDiskNumberResponse.DiskNumber, "volumeID", resp.VolumeId, "mountPath", mountPath)
	return strconv.Itoa(int(getDiskNumberResponse.DiskNumber)), 1, nil
}

// MakeDir creates a directory.
func (mounter *NodeMounter) MakeDir(pathname string) error {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.makeDir(csiProxyMounter, pathname)
	case *CSIProxyMounterV2:
		return mounter.makeDirV2(csiProxyMounter, pathname)
	default:
		return fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) makeDir(csiProxyMounter *CSIProxyMounter, pathname string) error {
	mkdirRequest := &fs.MkdirRequest{
		Path: util.NormalizeWindowsPath(pathname),
	}
	_, err := csiProxyMounter.FsClient.Mkdir(context.Background(), mkdirRequest)
	return err
}

// PathExists checks if the path exists.
func (mounter *NodeMounter) PathExists(path string) (bool, error) {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.pathExists(csiProxyMounter, path)
	case *CSIProxyMounterV2:
		return mounter.pathExistsV2(csiProxyMounter, path)
	default:
		return false, fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) pathExists(csiProxyMounter *CSIProxyMounter, path string) (bool, error) {
	isExistsResponse, err := csiProxyMounter.FsClient.PathExists(context.Background(),
		&fs.PathExistsRequest{
			Path: util.NormalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return isExistsResponse.Exists, nil
}

// NeedResize checks if the volume needs to be resized.
func (mounter *NodeMounter) NeedResize(devicePath, deviceMountPath string) (bool, error) {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.needResize(csiProxyMounter, devicePath, deviceMountPath)
	case *CSIProxyMounterV2:
		return mounter.needResizeV2(csiProxyMounter, devicePath, deviceMountPath)
	default:
		return false, fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) needResize(csiProxyMounter *CSIProxyMounter, devicePath, deviceMountPath string) (bool, error) {
	deviceSize, err := csiProxyMounter.GetDeviceSize(devicePath)
	if err != nil {
		return false, err
	}

	fsSize, err := csiProxyMounter.GetVolumeSizeInBytes(deviceMountPath)
	if err != nil {
		return false, err
	}
	// Tolerate one block difference (4096 bytes)
	if deviceSize <= util.DefaultBlockSize+fsSize {
		return true, nil
	}
	return false, nil
}

// Unpublish unpublishes the volume.
func (mounter *NodeMounter) Unpublish(target string) error {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.unpublish(csiProxyMounter, target)
	case *CSIProxyMounterV2:
		return mounter.unpublishV2(csiProxyMounter, target)
	default:
		return fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) unpublish(csiProxyMounter *CSIProxyMounter, target string) error {
	return csiProxyMounter.Rmdir(target)
}

// Unstage unmounts the volume.
func (mounter *NodeMounter) Unstage(target string) error {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.unstage(csiProxyMounter, target)
	case *CSIProxyMounterV2:
		return mounter.unstageV2(csiProxyMounter, target)
	default:
		return fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) unstage(csiProxyMounter *CSIProxyMounter, target string) error {
	return csiProxyMounter.Unmount(target)
}

// Resize resizes the volume.
func (mounter *NodeMounter) Resize(devicePath, deviceMountPath string) (bool, error) {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.resize(csiProxyMounter, devicePath, deviceMountPath)
	case *CSIProxyMounterV2:
		return mounter.resizeV2(csiProxyMounter, devicePath, deviceMountPath)
	default:
		return false, fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) resize(csiProxyMounter *CSIProxyMounter, _, deviceMountPath string) (bool, error) {
	// Find the volume id
	getVolumeIdRequest := &volume.GetVolumeIDFromTargetPathRequest{
		TargetPath: util.NormalizeWindowsPath(deviceMountPath),
	}
	volumeIdResponse, err := csiProxyMounter.VolumeClient.GetVolumeIDFromTargetPath(context.Background(), getVolumeIdRequest)
	if err != nil {
		return false, err
	}

	// Resize volume
	resizeVolumeRequest := &volume.ResizeVolumeRequest{
		VolumeId: volumeIdResponse.VolumeId,
	}
	_, err = csiProxyMounter.VolumeClient.ResizeVolume(context.Background(), resizeVolumeRequest)
	if err != nil {
		return false, err
	}

	return true, nil
}

// FindDevicePath returns the disk number for the given device path and volume ID.
func (mounter *NodeMounter) FindDevicePath(devicePath, volumeID, partition, region string) (string, error) {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.findDevicePath(csiProxyMounter, devicePath, volumeID)
	case *CSIProxyMounterV2:
		return mounter.findDevicePathV2(csiProxyMounter, devicePath, volumeID)
	default:
		return "", fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) findDevicePath(csiProxyMounter *CSIProxyMounter, devicePath, volumeID string) (string, error) {
	response, err := csiProxyMounter.DiskClient.ListDiskIDs(context.TODO(), &disk.ListDiskIDsRequest{})
	if err != nil {
		return "", fmt.Errorf("error listing disk ids: %q", err)
	}

	diskIDs := response.GetDiskIDs()

	foundDiskNumber := ""
	for diskNumber, diskID := range diskIDs {
		serialNumber := diskID.GetSerialNumber()
		cleanVolumeID := strings.ReplaceAll(volumeID, "-", "")
		if strings.Contains(serialNumber, cleanVolumeID) {
			foundDiskNumber = strconv.Itoa(int(diskNumber))
			break
		}
	}

	if foundDiskNumber == "" {
		return "", fmt.Errorf("disk number for device path %q volume id %q not found", devicePath, volumeID)
	}

	return foundDiskNumber, nil
}

// PreparePublishTarget prepares the target for publishing by deleting the target if it already exists.
func (mounter *NodeMounter) PreparePublishTarget(target string) error {
	// On Windows, Mount will create the parent of target and mklink (create a symbolic link) at target later, so don't create a
	// directory at target now. Otherwise mklink will error: "Cannot create a file when that file already exists".
	// Instead, delete the target if it already exists (like if it was created by kubelet <1.20)
	// https://github.com/kubernetes/kubernetes/pull/88759
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.preparePublishTarget(csiProxyMounter, target)
	case *CSIProxyMounterV2:
		return mounter.preparePublishTargetV2(csiProxyMounter, target)
	default:
		return fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) preparePublishTarget(csiProxyMounter *CSIProxyMounter, target string) error {
	exists, err := mounter.PathExists(target)
	if err != nil {
		return fmt.Errorf("error checking path %q exists: %v", target, err)
	}

	if exists {
		if err := csiProxyMounter.Rmdir(target); err != nil {
			return fmt.Errorf("error Rmdir target %q: %v", target, err)
		}
	}
	return nil
}

// IsCorruptedMnt checks if the error is due to a corrupted mount
func (mounter *NodeMounter) IsCorruptedMnt(err error) bool {
	return mountutils.IsCorruptedMnt(err)
}

// GetBlockSizeBytes returns the block size of the device in bytes
func (mounter *NodeMounter) GetBlockSizeBytes(devicePath string) (int64, error) {
	switch csiProxyMounter := mounter.SafeFormatAndMount.Interface.(type) {
	case *CSIProxyMounter:
		return mounter.getBlockSizeBytes(csiProxyMounter, devicePath)
	case *CSIProxyMounterV2:
		return mounter.getBlockSizeBytesV2(csiProxyMounter, devicePath)
	default:
		return -1, fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}
}

func (mounter *NodeMounter) getBlockSizeBytes(csiProxyMounter *CSIProxyMounter, devicePath string) (int64, error) {
	diskNumber, err := strconv.Atoi(devicePath)
	if err != nil {
		return -1, err
	}

	// Get size of the disk
	getDiskStatsRequest := &disk.GetDiskStatsRequest{
		DiskNumber: uint32(diskNumber),
	}
	resp, err := csiProxyMounter.DiskClient.GetDiskStats(context.Background(), getDiskStatsRequest)
	if err != nil {
		return -1, err
	}

	return resp.TotalBytes, nil
}

func (mounter *NodeMounter) MakeFile(pathname string) error {
	return fmt.Errorf("MakeFile not implemented for CSIProxyMounter")
}

func (mounter *NodeMounter) IsBlockDevice(fullPath string) (bool, error) {
	return false, nil
}

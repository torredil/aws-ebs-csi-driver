//go:build windows

/*
Copyright 2024 The Kubernetes Authors.

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
	"errors"
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

// Mount just creates a soft link at target pointing to source.
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

// Rmdir - delete the given directory
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

func (mounter *CSIProxyMounter) WriteVolumeCache(target string) {
	request := &volume.GetVolumeIDFromTargetPathRequest{TargetPath: util.NormalizeWindowsPath(target)}
	response, err := mounter.VolumeClient.GetVolumeIDFromTargetPath(context.Background(), request)
	if err != nil || response == nil {
		klog.InfoS("GetVolumeIDFromTargetPath failed", "target", target, "err", err, "response", response)
	} else {
		request := &volume.WriteVolumeCacheRequest{
			VolumeId: response.VolumeId,
		}
		if res, err := mounter.VolumeClient.WriteVolumeCache(context.Background(), request); err != nil {
			klog.InfoS("WriteVolumeCache failed", "volumeID", response.VolumeId, "err", err, "res", res)
		}
	}
}

func (mounter *CSIProxyMounter) List() ([]mountutils.MountPoint, error) {
	return []mountutils.MountPoint{}, errors.New("List not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) IsMountPointMatch(mp mountutils.MountPoint, dir string) bool {
	return mp.Path == dir
}

// IsMountPoint: determines if a directory is a mountpoint.
func (mounter *CSIProxyMounter) IsMountPoint(file string) (bool, error) {
	isNotMnt, err := mounter.IsLikelyNotMountPoint(file)
	if err != nil {
		return false, err
	}
	return !isNotMnt, nil
}

// IsLikelyMountPoint - If the directory does not exists, the function will return os.ErrNotExist error.
//
//	If the path exists, call to CSI proxy will check if its a link, if its a link then existence of target
//	path is checked.
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

func (mounter *CSIProxyMounter) PathIsDevice(pathname string) (bool, error) {
	return false, errors.New("PathIsDevice not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) DeviceOpened(pathname string) (bool, error) {
	return false, errors.New("DeviceOpened not implemented for CSIProxyMounter")
}

// GetDeviceNameFromMount returns the disk number for a mount path.
func (mounter *CSIProxyMounter) GetDeviceNameFromMount(mountPath, _ string) (string, error) {
	req := &volume.GetVolumeIDFromTargetPathRequest{TargetPath: util.NormalizeWindowsPath(mountPath)}
	resp, err := mounter.VolumeClient.GetVolumeIDFromTargetPath(context.Background(), req)
	if err != nil {
		return "", err
	}
	// Get disk number
	getDiskNumberRequest := &volume.GetDiskNumberFromVolumeIDRequest{
		VolumeId: resp.VolumeId,
	}
	getDiskNumberResponse, err := mounter.VolumeClient.GetDiskNumberFromVolumeID(context.Background(), getDiskNumberRequest)
	if err != nil {
		return "", err
	}
	klog.V(4).InfoS("GetDeviceNameFromMount called", "diskNumber", getDiskNumberResponse.DiskNumber, "volumeID", resp.VolumeId, "mountPath", mountPath)
	return fmt.Sprint(getDiskNumberResponse.DiskNumber), nil
}

func (mounter *CSIProxyMounter) MakeRShared(path string) error {
	return errors.New("MakeRShared not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) MakeFile(pathname string) error {
	return errors.New("MakeFile not implemented for CSIProxyMounter")
}

// MakeDir - Creates a directory. The CSI proxy takes in context information.
// Currently the make dir is only used from the staging code path, hence we call it
// with Plugin context..
func (mounter *CSIProxyMounter) MakeDir(pathname string) error {
	mkdirReq := &fs.MkdirRequest{
		Path: util.NormalizeWindowsPath(pathname),
	}
	_, err := mounter.FsClient.Mkdir(context.Background(), mkdirReq)
	if err != nil {
		klog.V(4).InfoS("Error", err)
		return err
	}

	return nil
}

// ExistsPath - Checks if a path exists. Unlike util ExistsPath, this call does not perform follow link.
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

func (mounter *CSIProxyMounter) EvalHostSymlinks(pathname string) (string, error) {
	return "", errors.New("EvalHostSymlinks is not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) GetMountRefs(pathname string) ([]string, error) {
	return []string{}, errors.New("GetMountRefs is not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) GetFSGroup(pathname string) (int64, error) {
	return -1, errors.New("GetFSGroup is not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) GetSELinuxSupport(pathname string) (bool, error) {
	return false, errors.New("GetSELinuxSupport is not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) GetMode(pathname string) (os.FileMode, error) {
	return 0, errors.New("GetMode is not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) MountSensitive(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	return errors.New("MountSensitive is not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) MountSensitiveWithoutSystemd(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	return errors.New("MountSensitiveWithoutSystemd is not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounter) MountSensitiveWithoutSystemdWithMountFlags(source string, target string, fstype string, options []string, sensitiveOptions []string, mountFlags []string) error {
	return errors.New("MountSensitiveWithoutSystemdWithMountFlags is not implemented for CSIProxyMounter")
}

// Rescan would trigger an update storage cache via the CSI proxy.
func (mounter *CSIProxyMounter) Rescan() error {
	// Call Rescan from disk APIs of CSI Proxy.
	if _, err := mounter.DiskClient.Rescan(context.Background(), &disk.RescanRequest{}); err != nil {
		return err
	}
	return nil
}

// FindDiskByLun - given a lun number, find out the corresponding disk
func (mounter *CSIProxyMounter) FindDiskByLun(lun string) (diskNum string, err error) {
	findDiskByLunResponse, err := mounter.DiskClient.ListDiskLocations(context.Background(), &disk.ListDiskLocationsRequest{})
	if err != nil {
		return "", err
	}

	// List all disk locations and match the lun id being requested for.
	// If match is found then return back the disk number.
	for diskID, location := range findDiskByLunResponse.DiskLocations {
		if strings.EqualFold(location.LUNID, lun) {
			return strconv.Itoa(int(diskID)), nil
		}
	}
	return "", fmt.Errorf("could not find disk id for lun: %s", lun)
}

// FormatAndMount - accepts the source disk number, target path to mount, the fstype to format with and options to be used.
func (mounter *CSIProxyMounter) FormatAndMountSensitiveWithFormatOptions(source string, target string, fstype string, options []string, sensitiveOptions []string, formatOptions []string) error {
	// sensitiveOptions is not supported on Windows because we have no reasonable way to control what the csi-proxy does
	if len(sensitiveOptions) > 0 {
		return errors.New("sensitiveOptions not supported on Windows!")
	}
	// formatOptions is not supported on Windows because the csi-proxy does not allow supplying format arguments
	// This limitation will be addressed in the future with privileged Windows containers
	if len(formatOptions) > 0 {
		return errors.New("formatOptions not supported on Windows!")
	}

	diskNumber, err := strconv.Atoi(source)
	if err != nil {
		return err
	}

	// Call PartitionDisk CSI proxy call to partition the disk and return the volume id
	partionDiskRequest := &disk.PartitionDiskRequest{
		DiskNumber: uint32(diskNumber),
	}
	_, err = mounter.DiskClient.PartitionDisk(context.Background(), partionDiskRequest)
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
	volumeIdResponse, err := mounter.VolumeClient.ListVolumesOnDisk(context.Background(), volumeIDsRequest)
	if err != nil {
		return err
	}

	// TODO: consider partitions and choose the right partition.
	// For now just choose the first volume.
	volumeID := volumeIdResponse.VolumeIds[0]

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
			// TODO: Accept the filesystem and other options
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

// ResizeVolume resizes the volume at given mount path
func (mounter *CSIProxyMounter) ResizeVolume(deviceMountPath string) (bool, error) {
	// Find the volume id
	getVolumeIdRequest := &volume.GetVolumeIDFromTargetPathRequest{
		TargetPath: util.NormalizeWindowsPath(deviceMountPath),
	}
	volumeIdResponse, err := mounter.VolumeClient.GetVolumeIDFromTargetPath(context.Background(), getVolumeIdRequest)
	if err != nil {
		return false, err
	}
	volumeId := volumeIdResponse.GetVolumeId()

	// Resize volume
	resizeVolumeRequest := &volume.ResizeVolumeRequest{
		VolumeId: volumeId,
	}
	_, err = mounter.VolumeClient.ResizeVolume(context.Background(), resizeVolumeRequest)
	if err != nil {
		return false, err
	}

	return true, nil
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

func (mounter *CSIProxyMounter) CanSafelySkipMountPointCheck() bool {
	return false
}

func (mounter *CSIProxyMounter) FindDevicePath(devicePath, volumeID, _, _ string) (string, error) {
	diskClient, err := diskclient.NewClient()
	if err != nil {
		return "", fmt.Errorf("error creating csi-proxy disk client: %q", err)
	}
	defer diskClient.Close()

	response, err := diskClient.ListDiskIDs(context.TODO(), &disk.ListDiskIDsRequest{})
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

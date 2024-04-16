//go:build windows
// +build windows

package mounter

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	diskv2 "github.com/kubernetes-csi/csi-proxy/v2/pkg/disk"
	diskapiv2 "github.com/kubernetes-csi/csi-proxy/v2/pkg/disk/hostapi"
	fsv2 "github.com/kubernetes-csi/csi-proxy/v2/pkg/filesystem"
	fsapiv2 "github.com/kubernetes-csi/csi-proxy/v2/pkg/filesystem/hostapi"
	volumev2 "github.com/kubernetes-csi/csi-proxy/v2/pkg/volume"
	volumeapiv2 "github.com/kubernetes-csi/csi-proxy/v2/pkg/volume/hostapi"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/util"
	"k8s.io/klog/v2"
	mountutils "k8s.io/mount-utils"
	utilexec "k8s.io/utils/exec"
)

type CSIProxyMounterV2 struct {
	Fs     fsv2.Interface
	Disk   diskv2.Interface
	Volume volumev2.Interface
}

// NewSafeMounterV2 returns a new instance of SafeFormatAndMount.
func NewSafeMounterV2() (*mountutils.SafeFormatAndMount, error) {
	fs, err := fsv2.New(fsapiv2.New())
	if err != nil {
		return nil, err
	}
	disk, err := diskv2.New(diskapiv2.New())
	if err != nil {
		return nil, err
	}
	volume, err := volumev2.New(volumeapiv2.New())
	if err != nil {
		return nil, err
	}
	return &mountutils.SafeFormatAndMount{
		Interface: &CSIProxyMounterV2{
			Fs:     fs,
			Disk:   disk,
			Volume: volume,
		},
		Exec: utilexec.New(),
	}, nil
}

// Mount mounts the volume.
func (mounter *CSIProxyMounterV2) Mount(source string, target string, fstype string, options []string) error {
	linkRequest := &fsv2.CreateSymlinkRequest{
		SourcePath: util.NormalizeWindowsPath(source),
		TargetPath: util.NormalizeWindowsPath(target),
	}
	_, err := mounter.Fs.CreateSymlink(context.Background(), linkRequest)
	if err != nil {
		return err
	}
	return nil
}

// Unmount unmounts the volume.
func (mounter *CSIProxyMounterV2) Unmount(target string) error {
	getVolumeIdRequest := &volumev2.GetVolumeIDFromTargetPathRequest{
		TargetPath: util.NormalizeWindowsPath(target),
	}
	volumeIdResponse, err := mounter.Volume.GetVolumeIDFromTargetPath(context.Background(), getVolumeIdRequest)
	if err != nil {
		return err
	}

	unmountVolumeRequest := &volumev2.UnmountVolumeRequest{
		VolumeID:   volumeIdResponse.VolumeID,
		TargetPath: util.NormalizeWindowsPath(target),
	}
	_, err = mounter.Volume.UnmountVolume(context.Background(), unmountVolumeRequest)
	if err != nil {
		return err
	}

	rmdirRequest := &fsv2.RmdirRequest{
		Path:  target,
		Force: true,
	}

	_, err = mounter.Fs.Rmdir(context.Background(), rmdirRequest)

	getDiskNumberRequest := &volumev2.GetDiskNumberFromVolumeIDRequest{
		VolumeID: volumeIdResponse.VolumeID,
	}
	getDiskNumberResponse, err := mounter.Volume.GetDiskNumberFromVolumeID(context.Background(), getDiskNumberRequest)
	if err != nil {
		return err
	}

	setDiskStateRequest := &diskv2.SetDiskStateRequest{
		DiskNumber: getDiskNumberResponse.DiskNumber,
		IsOnline:   false,
	}
	_, err = mounter.Disk.SetDiskState(context.Background(), setDiskStateRequest)
	if err != nil {
		return err
	}
	klog.V(4).InfoS("Successfully unmounted volume", "diskNumber", getDiskNumberResponse.DiskNumber, "volumeId", volumeIdResponse.VolumeID, "target", target)
	return nil
}

// ExistsPath checks if a path exists.
func (mounter *CSIProxyMounterV2) ExistsPath(path string) (bool, error) {
	isExistsResponse, err := mounter.Fs.PathExists(context.Background(),
		&fsv2.PathExistsRequest{
			Path: util.NormalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return isExistsResponse.Exists, err
}

// IsLikelyNotMountPoint checks if the path is a mount point.
func (mounter *CSIProxyMounterV2) IsLikelyNotMountPoint(path string) (bool, error) {
	isExists, err := mounter.ExistsPath(path)
	if err != nil {
		return false, err
	}
	if !isExists {
		return true, os.ErrNotExist
	}

	response, err := mounter.Fs.IsSymlink(context.Background(),
		&fsv2.IsSymlinkRequest{
			Path: util.NormalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return !response.IsSymlink, nil
}

// GetDeviceSize returns the size of the disk in bytes
func (mounter *CSIProxyMounterV2) GetDeviceSize(disk string) (int64, error) {
	diskNumber, err := strconv.Atoi(disk)
	if err != nil {
		return -1, err
	}

	//Get size of the disk
	getDiskStatsRequest := &diskv2.GetDiskStatsRequest{
		DiskNumber: uint32(diskNumber),
	}
	resp, err := mounter.Disk.GetDiskStats(context.Background(), getDiskStatsRequest)
	if err != nil {
		return -1, err
	}

	return resp.TotalBytes, nil
}

// GetVolumeSizeInBytes returns the size of the volume in bytes
func (mounter *CSIProxyMounterV2) GetVolumeSizeInBytes(deviceMountPath string) (int64, error) {
	// Find the volume id
	getVolumeIdRequest := &volumev2.GetVolumeIDFromTargetPathRequest{
		TargetPath: util.NormalizeWindowsPath(deviceMountPath),
	}
	volumeIdResponse, err := mounter.Volume.GetVolumeIDFromTargetPath(context.Background(), getVolumeIdRequest)
	if err != nil {
		return -1, err
	}
	volumeId := volumeIdResponse.VolumeID

	// Get size of the volume
	getVolumeStatsRequest := &volumev2.GetVolumeStatsRequest{
		VolumeID: volumeId,
	}
	resp, err := mounter.Volume.GetVolumeStats(context.Background(), getVolumeStatsRequest)
	if err != nil {
		return -1, err
	}

	return resp.TotalBytes, nil
}

// FormatAndMountSensitiveWithFormatOptions formats and mounts the volume.
func (mounter *CSIProxyMounterV2) FormatAndMountSensitiveWithFormatOptions(source string, target string, fstype string, options []string, sensitiveOptions []string, formatOptions []string) error {
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
	partitionDiskRequest := &diskv2.PartitionDiskRequest{
		DiskNumber: uint32(diskNumber),
	}
	_, err = mounter.Disk.PartitionDisk(context.Background(), partitionDiskRequest)
	if err != nil {
		return err
	}

	// Ensure the disk is online before mounting.
	setDiskStateRequest := &diskv2.SetDiskStateRequest{
		DiskNumber: uint32(diskNumber),
		IsOnline:   true,
	}
	_, err = mounter.Disk.SetDiskState(context.Background(), setDiskStateRequest)
	if err != nil {
		return err
	}

	// List the volumes on the given disk.
	volumeIDsRequest := &volumev2.ListVolumesOnDiskRequest{
		DiskNumber: uint32(diskNumber),
	}
	volumeIDResponse, err := mounter.Volume.ListVolumesOnDisk(context.Background(), volumeIDsRequest)
	if err != nil {
		return err
	}

	// TODO: consider partitions and choose the right partition.
	// For now just choose the first volume.
	volumeID := volumeIDResponse.VolumeIDs[0]

	// Check if the volume is formatted.
	isVolumeFormattedRequest := &volumev2.IsVolumeFormattedRequest{
		VolumeID: volumeID,
	}
	isVolumeFormattedResponse, err := mounter.Volume.IsVolumeFormatted(context.Background(), isVolumeFormattedRequest)
	if err != nil {
		return err
	}

	// If the volume is not formatted, then format it, else proceed to mount.
	if !isVolumeFormattedResponse.Formatted {
		formatVolumeRequest := &volumev2.FormatVolumeRequest{
			VolumeID: volumeID,
		}
		_, err = mounter.Volume.FormatVolume(context.Background(), formatVolumeRequest)
		if err != nil {
			return err
		}
	}

	// Mount the volume by calling the CSI proxy call.
	mountVolumeRequest := &volumev2.MountVolumeRequest{
		VolumeID:   volumeID,
		TargetPath: util.NormalizeWindowsPath(target),
	}
	_, err = mounter.Volume.MountVolume(context.Background(), mountVolumeRequest)
	if err != nil {
		return err
	}
	return nil
}

func (mounter *CSIProxyMounterV2) List() ([]mountutils.MountPoint, error) {
	return []mountutils.MountPoint{}, fmt.Errorf("List not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounterV2) CanSafelySkipMountPointCheck() bool {
	return false
}

func (mounter *CSIProxyMounterV2) GetMountRefs(string) ([]string, error) {
	return nil, fmt.Errorf("GetMountRefs not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounterV2) IsMountPoint(string) (bool, error) {
	return false, fmt.Errorf("GetMountRefs not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounterV2) MountSensitive(string, string, string, []string, []string) error {
	return fmt.Errorf("MountSensitive not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounterV2) MountSensitiveWithoutSystemd(string, string, string, []string, []string) error {
	return fmt.Errorf("MountSensitiveWithoutSystemd not implemented for CSIProxyMounter")
}

func (mounter *CSIProxyMounterV2) MountSensitiveWithoutSystemdWithMountFlags(string, string, string, []string, []string, []string) error {
	return fmt.Errorf("MountSensitiveWithoutSystemdWithMountFlags not implemented for CSIProxyMounter")
}

func getDeviceNameFromMountV2(mounter mountutils.Interface, mountPath string) (string, int, error) {
	csiProxyMounter, ok := mounter.(*CSIProxyMounterV2)
	if !ok {
		return "", 0, fmt.Errorf("failed to cast mounter to CSI proxy mounter")
	}

	req := &volumev2.GetVolumeIDFromTargetPathRequest{TargetPath: util.NormalizeWindowsPath(mountPath)}
	resp, err := csiProxyMounter.Volume.GetVolumeIDFromTargetPath(context.Background(), req)
	if err != nil {
		return "", 0, err
	}
	// Get disk number
	getDiskNumberRequest := &volumev2.GetDiskNumberFromVolumeIDRequest{
		VolumeID: resp.VolumeID,
	}
	getDiskNumberResponse, err := csiProxyMounter.Volume.GetDiskNumberFromVolumeID(context.Background(), getDiskNumberRequest)
	if err != nil {
		return "", 0, err
	}
	klog.V(4).InfoS("GetDeviceNameFromMount called", "diskNumber", getDiskNumberResponse.DiskNumber, "volumeID", resp.VolumeID, "mountPath", mountPath)
	return strconv.Itoa(int(getDiskNumberResponse.DiskNumber)), 1, nil
}

func (mounter *NodeMounter) makeDirV2(csiProxyMounter *CSIProxyMounterV2, pathname string) error {
	mkdirRequest := &fsv2.MkdirRequest{
		Path: util.NormalizeWindowsPath(pathname),
	}
	_, err := csiProxyMounter.Fs.Mkdir(context.Background(), mkdirRequest)
	return err
}

func (mounter *NodeMounter) pathExistsV2(csiProxyMounter *CSIProxyMounterV2, path string) (bool, error) {
	isExistsResponse, err := csiProxyMounter.Fs.PathExists(context.Background(),
		&fsv2.PathExistsRequest{
			Path: util.NormalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return isExistsResponse.Exists, nil
}

func (mounter *NodeMounter) needResizeV2(csiProxyMounter *CSIProxyMounterV2, devicePath, deviceMountPath string) (bool, error) {
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

func (mounter *NodeMounter) unpublishV2(csiProxyMounter *CSIProxyMounterV2, target string) error {
	rmdirRequest := &fsv2.RmdirRequest{
		Path:  target,
		Force: true,
	}
	_, err := csiProxyMounter.Fs.Rmdir(context.Background(), rmdirRequest)
	return err
}

func (mounter *NodeMounter) unstageV2(csiProxyMounter *CSIProxyMounterV2, target string) error {
	return csiProxyMounter.Unmount(target)
}

func (mounter *NodeMounter) resizeV2(csiProxyMounter *CSIProxyMounterV2, _, deviceMountPath string) (bool, error) {
	// Find the volume id
	getVolumeIdRequest := &volumev2.GetVolumeIDFromTargetPathRequest{
		TargetPath: util.NormalizeWindowsPath(deviceMountPath),
	}
	volumeIdResponse, err := csiProxyMounter.Volume.GetVolumeIDFromTargetPath(context.Background(), getVolumeIdRequest)
	if err != nil {
		return false, err
	}

	// Resize volume
	resizeVolumeRequest := &volumev2.ResizeVolumeRequest{
		VolumeID: volumeIdResponse.VolumeID,
	}
	_, err = csiProxyMounter.Volume.ResizeVolume(context.Background(), resizeVolumeRequest)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (mounter *NodeMounter) findDevicePathV2(csiProxyMounter *CSIProxyMounterV2, devicePath, volumeID string) (string, error) {
	response, err := csiProxyMounter.Disk.ListDiskIDs(context.TODO(), &diskv2.ListDiskIDsRequest{})
	if err != nil {
		return "", fmt.Errorf("error listing disk ids: %q", err)
	}

	diskIDs := response.DiskIDs

	foundDiskNumber := ""
	for diskNumber, diskID := range diskIDs {
		serialNumber := diskID.SerialNumber
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

func (mounter *NodeMounter) preparePublishTargetV2(csiProxyMounter *CSIProxyMounterV2, target string) error {
	exists, err := mounter.PathExists(target)
	if err != nil {
		return fmt.Errorf("error checking path %q exists: %v", target, err)
	}

	if exists {
		rmdirRequest := &fsv2.RmdirRequest{
			Path:  target,
			Force: true,
		}
		_, err := csiProxyMounter.Fs.Rmdir(context.Background(), rmdirRequest)
		if err != nil {
			return fmt.Errorf("error Rmdir target %q: %v", target, err)
		}
	}
	return nil
}

func (mounter *NodeMounter) getBlockSizeBytesV2(csiProxyMounter *CSIProxyMounterV2, devicePath string) (int64, error) {
	diskNumber, err := strconv.Atoi(devicePath)
	if err != nil {
		return -1, err
	}

	// Get size of the disk
	getDiskStatsRequest := &diskv2.GetDiskStatsRequest{
		DiskNumber: uint32(diskNumber),
	}
	resp, err := csiProxyMounter.Disk.GetDiskStats(context.Background(), getDiskStatsRequest)
	if err != nil {
		return -1, err
	}

	return resp.TotalBytes, nil
}

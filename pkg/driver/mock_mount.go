// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/driver/mount.go

// Package driver is a generated GoMock package.
package driver

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	mount "k8s.io/mount-utils"
)

// MockMounter is a mock of Mounter interface.
type MockMounter struct {
	ctrl     *gomock.Controller
	recorder *MockMounterMockRecorder
}

// MockMounterMockRecorder is the mock recorder for MockMounter.
type MockMounterMockRecorder struct {
	mock *MockMounter
}

// NewMockMounter creates a new mock instance.
func NewMockMounter(ctrl *gomock.Controller) *MockMounter {
	mock := &MockMounter{ctrl: ctrl}
	mock.recorder = &MockMounterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMounter) EXPECT() *MockMounterMockRecorder {
	return m.recorder
}

// CanSafelySkipMountPointCheck mocks base method.
func (m *MockMounter) CanSafelySkipMountPointCheck() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CanSafelySkipMountPointCheck")
	ret0, _ := ret[0].(bool)
	return ret0
}

// CanSafelySkipMountPointCheck indicates an expected call of CanSafelySkipMountPointCheck.
func (mr *MockMounterMockRecorder) CanSafelySkipMountPointCheck() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CanSafelySkipMountPointCheck", reflect.TypeOf((*MockMounter)(nil).CanSafelySkipMountPointCheck))
}

// FindDevicePath mocks base method.
func (m *MockMounter) FindDevicePath(devicePath, volumeID, partition, region string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindDevicePath", devicePath, volumeID, partition, region)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindDevicePath indicates an expected call of FindDevicePath.
func (mr *MockMounterMockRecorder) FindDevicePath(devicePath, volumeID, partition, region interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindDevicePath", reflect.TypeOf((*MockMounter)(nil).FindDevicePath), devicePath, volumeID, partition, region)
}

// FormatAndMountSensitiveWithFormatOptions mocks base method.
func (m *MockMounter) FormatAndMountSensitiveWithFormatOptions(source, target, fstype string, options, sensitiveOptions, formatOptions []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FormatAndMountSensitiveWithFormatOptions", source, target, fstype, options, sensitiveOptions, formatOptions)
	ret0, _ := ret[0].(error)
	return ret0
}

// FormatAndMountSensitiveWithFormatOptions indicates an expected call of FormatAndMountSensitiveWithFormatOptions.
func (mr *MockMounterMockRecorder) FormatAndMountSensitiveWithFormatOptions(source, target, fstype, options, sensitiveOptions, formatOptions interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FormatAndMountSensitiveWithFormatOptions", reflect.TypeOf((*MockMounter)(nil).FormatAndMountSensitiveWithFormatOptions), source, target, fstype, options, sensitiveOptions, formatOptions)
}

// GetBlockSizeBytes mocks base method.
func (m *MockMounter) GetBlockSizeBytes(devicePath string) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBlockSizeBytes", devicePath)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBlockSizeBytes indicates an expected call of GetBlockSizeBytes.
func (mr *MockMounterMockRecorder) GetBlockSizeBytes(devicePath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBlockSizeBytes", reflect.TypeOf((*MockMounter)(nil).GetBlockSizeBytes), devicePath)
}

// GetDeviceNameFromMount mocks base method.
func (m *MockMounter) GetDeviceNameFromMount(mountPath string) (string, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDeviceNameFromMount", mountPath)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetDeviceNameFromMount indicates an expected call of GetDeviceNameFromMount.
func (mr *MockMounterMockRecorder) GetDeviceNameFromMount(mountPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDeviceNameFromMount", reflect.TypeOf((*MockMounter)(nil).GetDeviceNameFromMount), mountPath)
}

// GetMountRefs mocks base method.
func (m *MockMounter) GetMountRefs(pathname string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMountRefs", pathname)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMountRefs indicates an expected call of GetMountRefs.
func (mr *MockMounterMockRecorder) GetMountRefs(pathname interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMountRefs", reflect.TypeOf((*MockMounter)(nil).GetMountRefs), pathname)
}

// IsBlockDevice mocks base method.
func (m *MockMounter) IsBlockDevice(fullPath string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsBlockDevice", fullPath)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsBlockDevice indicates an expected call of IsBlockDevice.
func (mr *MockMounterMockRecorder) IsBlockDevice(fullPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsBlockDevice", reflect.TypeOf((*MockMounter)(nil).IsBlockDevice), fullPath)
}

// IsCorruptedMnt mocks base method.
func (m *MockMounter) IsCorruptedMnt(err error) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsCorruptedMnt", err)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsCorruptedMnt indicates an expected call of IsCorruptedMnt.
func (mr *MockMounterMockRecorder) IsCorruptedMnt(err interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsCorruptedMnt", reflect.TypeOf((*MockMounter)(nil).IsCorruptedMnt), err)
}

// IsLikelyNotMountPoint mocks base method.
func (m *MockMounter) IsLikelyNotMountPoint(file string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsLikelyNotMountPoint", file)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsLikelyNotMountPoint indicates an expected call of IsLikelyNotMountPoint.
func (mr *MockMounterMockRecorder) IsLikelyNotMountPoint(file interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsLikelyNotMountPoint", reflect.TypeOf((*MockMounter)(nil).IsLikelyNotMountPoint), file)
}

// IsMountPoint mocks base method.
func (m *MockMounter) IsMountPoint(file string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsMountPoint", file)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsMountPoint indicates an expected call of IsMountPoint.
func (mr *MockMounterMockRecorder) IsMountPoint(file interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsMountPoint", reflect.TypeOf((*MockMounter)(nil).IsMountPoint), file)
}

// List mocks base method.
func (m *MockMounter) List() ([]mount.MountPoint, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List")
	ret0, _ := ret[0].([]mount.MountPoint)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockMounterMockRecorder) List() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockMounter)(nil).List))
}

// MakeDir mocks base method.
func (m *MockMounter) MakeDir(path string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MakeDir", path)
	ret0, _ := ret[0].(error)
	return ret0
}

// MakeDir indicates an expected call of MakeDir.
func (mr *MockMounterMockRecorder) MakeDir(path interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MakeDir", reflect.TypeOf((*MockMounter)(nil).MakeDir), path)
}

// MakeFile mocks base method.
func (m *MockMounter) MakeFile(path string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MakeFile", path)
	ret0, _ := ret[0].(error)
	return ret0
}

// MakeFile indicates an expected call of MakeFile.
func (mr *MockMounterMockRecorder) MakeFile(path interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MakeFile", reflect.TypeOf((*MockMounter)(nil).MakeFile), path)
}

// Mount mocks base method.
func (m *MockMounter) Mount(source, target, fstype string, options []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Mount", source, target, fstype, options)
	ret0, _ := ret[0].(error)
	return ret0
}

// Mount indicates an expected call of Mount.
func (mr *MockMounterMockRecorder) Mount(source, target, fstype, options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Mount", reflect.TypeOf((*MockMounter)(nil).Mount), source, target, fstype, options)
}

// MountSensitive mocks base method.
func (m *MockMounter) MountSensitive(source, target, fstype string, options, sensitiveOptions []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MountSensitive", source, target, fstype, options, sensitiveOptions)
	ret0, _ := ret[0].(error)
	return ret0
}

// MountSensitive indicates an expected call of MountSensitive.
func (mr *MockMounterMockRecorder) MountSensitive(source, target, fstype, options, sensitiveOptions interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MountSensitive", reflect.TypeOf((*MockMounter)(nil).MountSensitive), source, target, fstype, options, sensitiveOptions)
}

// MountSensitiveWithoutSystemd mocks base method.
func (m *MockMounter) MountSensitiveWithoutSystemd(source, target, fstype string, options, sensitiveOptions []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MountSensitiveWithoutSystemd", source, target, fstype, options, sensitiveOptions)
	ret0, _ := ret[0].(error)
	return ret0
}

// MountSensitiveWithoutSystemd indicates an expected call of MountSensitiveWithoutSystemd.
func (mr *MockMounterMockRecorder) MountSensitiveWithoutSystemd(source, target, fstype, options, sensitiveOptions interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MountSensitiveWithoutSystemd", reflect.TypeOf((*MockMounter)(nil).MountSensitiveWithoutSystemd), source, target, fstype, options, sensitiveOptions)
}

// MountSensitiveWithoutSystemdWithMountFlags mocks base method.
func (m *MockMounter) MountSensitiveWithoutSystemdWithMountFlags(source, target, fstype string, options, sensitiveOptions, mountFlags []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MountSensitiveWithoutSystemdWithMountFlags", source, target, fstype, options, sensitiveOptions, mountFlags)
	ret0, _ := ret[0].(error)
	return ret0
}

// MountSensitiveWithoutSystemdWithMountFlags indicates an expected call of MountSensitiveWithoutSystemdWithMountFlags.
func (mr *MockMounterMockRecorder) MountSensitiveWithoutSystemdWithMountFlags(source, target, fstype, options, sensitiveOptions, mountFlags interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MountSensitiveWithoutSystemdWithMountFlags", reflect.TypeOf((*MockMounter)(nil).MountSensitiveWithoutSystemdWithMountFlags), source, target, fstype, options, sensitiveOptions, mountFlags)
}

// NeedResize mocks base method.
func (m *MockMounter) NeedResize(devicePath, deviceMountPath string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NeedResize", devicePath, deviceMountPath)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NeedResize indicates an expected call of NeedResize.
func (mr *MockMounterMockRecorder) NeedResize(devicePath, deviceMountPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NeedResize", reflect.TypeOf((*MockMounter)(nil).NeedResize), devicePath, deviceMountPath)
}

// PathExists mocks base method.
func (m *MockMounter) PathExists(path string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PathExists", path)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PathExists indicates an expected call of PathExists.
func (mr *MockMounterMockRecorder) PathExists(path interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PathExists", reflect.TypeOf((*MockMounter)(nil).PathExists), path)
}

// PreparePublishTarget mocks base method.
func (m *MockMounter) PreparePublishTarget(target string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PreparePublishTarget", target)
	ret0, _ := ret[0].(error)
	return ret0
}

// PreparePublishTarget indicates an expected call of PreparePublishTarget.
func (mr *MockMounterMockRecorder) PreparePublishTarget(target interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PreparePublishTarget", reflect.TypeOf((*MockMounter)(nil).PreparePublishTarget), target)
}

// Resize mocks base method.
func (m *MockMounter) Resize(devicePath, deviceMountPath string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resize", devicePath, deviceMountPath)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resize indicates an expected call of Resize.
func (mr *MockMounterMockRecorder) Resize(devicePath, deviceMountPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resize", reflect.TypeOf((*MockMounter)(nil).Resize), devicePath, deviceMountPath)
}

// Unmount mocks base method.
func (m *MockMounter) Unmount(target string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unmount", target)
	ret0, _ := ret[0].(error)
	return ret0
}

// Unmount indicates an expected call of Unmount.
func (mr *MockMounterMockRecorder) Unmount(target interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unmount", reflect.TypeOf((*MockMounter)(nil).Unmount), target)
}

// Unpublish mocks base method.
func (m *MockMounter) Unpublish(path string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unpublish", path)
	ret0, _ := ret[0].(error)
	return ret0
}

// Unpublish indicates an expected call of Unpublish.
func (mr *MockMounterMockRecorder) Unpublish(path interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unpublish", reflect.TypeOf((*MockMounter)(nil).Unpublish), path)
}

// Unstage mocks base method.
func (m *MockMounter) Unstage(path string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unstage", path)
	ret0, _ := ret[0].(error)
	return ret0
}

// Unstage indicates an expected call of Unstage.
func (mr *MockMounterMockRecorder) Unstage(path interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unstage", reflect.TypeOf((*MockMounter)(nil).Unstage), path)
}

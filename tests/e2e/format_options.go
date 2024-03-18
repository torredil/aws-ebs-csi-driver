/*
Copyright 2018 The Kubernetes Authors.

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

package e2e

import (
	"fmt"

	"github.com/kubernetes-sigs/aws-ebs-csi-driver/pkg/util"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/tests/e2e/driver"
	"github.com/kubernetes-sigs/aws-ebs-csi-driver/tests/e2e/testsuites"
	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

var (
	testedFsTypes = []string{util.FSTypeExt4, util.FSTypeExt3, util.FSTypeXfs}
)

var _ = Describe("[ebs-csi-e2e] [single-az] [format-options] Formatting a volume", func() {
	f := framework.NewDefaultFramework("ebs")
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	var (
		cs        clientset.Interface
		ns        *v1.Namespace
		ebsDriver driver.PVTestDriver
	)

	BeforeEach(func() {
		cs = f.ClientSet
		ns = f.Namespace
		ebsDriver = driver.InitEbsCSIDriver()
	})

	for _, fsType := range testedFsTypes {

		formatOptionTests := map[string]testsuites.FormatOptionTest{
			util.BlockSizeKey: {
				CreateVolumeParameters: map[string]string{
					util.BlockSizeKey: "1024",
					util.FSTypeKey:    fsType,
				},
			},
			util.InodeSizeKey: {
				CreateVolumeParameters: map[string]string{
					util.InodeSizeKey: "512",
					util.FSTypeKey:    fsType,
				},
			},
			util.BytesPerInodeKey: {
				CreateVolumeParameters: map[string]string{
					util.BytesPerInodeKey: "8192",
					util.FSTypeKey:        fsType,
				},
			},
			util.NumberOfInodesKey: {
				CreateVolumeParameters: map[string]string{
					util.NumberOfInodesKey: "200192",
					util.FSTypeKey:         fsType,
				},
			},
			util.Ext4BigAllocKey: {
				CreateVolumeParameters: map[string]string{
					util.Ext4BigAllocKey: "true",
					util.FSTypeKey:       fsType,
				},
			},
			util.Ext4ClusterSizeKey: {
				CreateVolumeParameters: map[string]string{
					util.Ext4BigAllocKey:    "true",
					util.Ext4ClusterSizeKey: "16384",
					util.FSTypeKey:          fsType,
				},
			},
		}

		Context(fmt.Sprintf("using an %s filesystem", fsType), func() {
			for testedParameter, formatOptionTestCase := range formatOptionTests {
				formatOptionTestCase := formatOptionTestCase
				if fsTypeDoesNotSupportFormatOptionParameter(fsType, testedParameter) {
					continue
				}

				Context(fmt.Sprintf("with a custom %s parameter", testedParameter), func() {
					It("successfully mounts and is resizable", func() {
						formatOptionTestCase.Run(cs, ns, ebsDriver)
					})
				})
			}
		})
	}
})

func fsTypeDoesNotSupportFormatOptionParameter(fsType string, createVolumeParameterKey string) bool {
	_, paramNotSupported := util.FileSystemConfigs[fsType].NotSupportedParams[createVolumeParameterKey]
	return paramNotSupported
}

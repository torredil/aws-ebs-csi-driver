# Copyright 2019 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# See
# https://docs.docker.com/engine/reference/builder/#automatic-platform-args-in-the-global-scope
# for info on BUILDPLATFORM, TARGETOS, TARGETARCH, etc.
FROM --platform=$BUILDPLATFORM golang:1.17 AS builder
WORKDIR /go/src/github.com/kubernetes-sigs/aws-ebs-csi-driver
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN OS=$TARGETOS ARCH=$TARGETARCH make $TARGETOS/$TARGETARCH

# Start from Kubernetes Debian base.
FROM k8s.gcr.io/build-image/debian-base:buster-v1.9.0 AS debian1
# Install necessary dependencies
RUN clean-install ca-certificates e2fsprogs xfsprogs util-linux mount udev
# Since we're leveraging apt to pull in dependencies, we use `gcr.io/distroless/base` because it includes glibc.
FROM gcr.io/distroless/base-debian11 AS debian
# Copy necessary dependencies into distroless base.
COPY --from=builder /go/src/github.com/kubernetes-sigs/aws-ebs-csi-driver/bin/aws-ebs-csi-driver /bin/aws-ebs-csi-driver
COPY --from=debian1 /etc/mke2fs.conf /etc/mke2fs.conf
COPY --from=debian1 /lib/udev/scsi_id /lib/udev_containerized/scsi_id
COPY --from=debian1 /bin/mount /bin/mount
COPY --from=debian1 /bin/umount /bin/umount
COPY --from=debian1 /sbin/blkid /sbin/blkid
COPY --from=debian1 /sbin/blockdev /sbin/blockdev
COPY --from=debian1 /sbin/dumpe2fs /sbin/dumpe2fs
COPY --from=debian1 /sbin/e* /sbin/
COPY --from=debian1 /sbin/e2fsck /sbin/e2fsck
COPY --from=debian1 /sbin/fsck /sbin/fsck
COPY --from=debian1 /sbin/fsck* /sbin/
COPY --from=debian1 /sbin/fsck.xfs /sbin/fsck.xfs
COPY --from=debian1 /sbin/mke2fs /sbin/mke2fs
COPY --from=debian1 /sbin/mkfs* /sbin/
COPY --from=debian1 /sbin/resize2fs /sbin/resize2fs
COPY --from=debian1 /sbin/xfs_repair /sbin/xfs_repair
COPY --from=debian1 /usr/include/xfs /usr/include/xfs
COPY --from=debian1 /usr/lib/xfsprogs/xfs* /usr/lib/xfsprogs/
COPY --from=debian1 /usr/sbin/xfs* /usr/sbin/

# Copy x86 shared libraries into distroless base.
COPY --from=debian1 /lib/x86_64-linux-gnu/libblkid.so.1 /lib/x86_64-linux-gnu/libblkid.so.1
COPY --from=debian1 /lib/x86_64-linux-gnu/libcom_err.so.2 /lib/x86_64-linux-gnu/libcom_err.so.2
COPY --from=debian1 /lib/x86_64-linux-gnu/libext2fs.so.2 /lib/x86_64-linux-gnu/libext2fs.so.2
COPY --from=debian1 /lib/x86_64-linux-gnu/libe2p.so.2 /lib/x86_64-linux-gnu/libe2p.so.2
COPY --from=debian1 /lib/x86_64-linux-gnu/libmount.so.1 /lib/x86_64-linux-gnu/libmount.so.1
COPY --from=debian1 /lib/x86_64-linux-gnu/libpcre.so.3 /lib/x86_64-linux-gnu/libpcre.so.3
COPY --from=debian1 /lib/x86_64-linux-gnu/libreadline.so.5 /lib/x86_64-linux-gnu/libreadline.so.5
COPY --from=debian1 /lib/x86_64-linux-gnu/libselinux.so.1 /lib/x86_64-linux-gnu/libselinux.so.1
COPY --from=debian1 /lib/x86_64-linux-gnu/libtinfo.so.6 /lib/x86_64-linux-gnu/libtinfo.so.6
COPY --from=debian1 /lib/x86_64-linux-gnu/libuuid.so.1 /lib/x86_64-linux-gnu/libuuid.so.1
ENTRYPOINT ["/bin/aws-ebs-csi-driver"]

FROM mcr.microsoft.com/windows/servercore:ltsc2019 AS ltsc2019
COPY --from=builder /go/src/github.com/kubernetes-sigs/aws-ebs-csi-driver/bin/aws-ebs-csi-driver.exe /aws-ebs-csi-driver.exe
ENTRYPOINT ["/aws-ebs-csi-driver.exe"]

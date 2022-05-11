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

FROM k8s.gcr.io/build-image/debian-base:bullseye-v1.2.0 as debian
RUN clean-install util-linux e2fsprogs mount ca-certificates udev xfsprogs

FROM gcr.io/distroless/static-debian11 AS distroless-amd64
ENV LIB_DIRECTORY /lib/x86_64-linux-gnu/
COPY --from=debian /lib64/ld-linux-x86-64.so.2 /lib64/

FROM gcr.io/distroless/static-debian11 AS distroless-arm64
ENV LIB_DIRECTORY /lib/aarch64-linux-gnu/
COPY --from=debian /lib/ld-linux-aarch64.so.1 /lib/

FROM distroless-$TARGETARCH as linux-distroless
COPY --from=builder /go/src/github.com/kubernetes-sigs/aws-ebs-csi-driver/bin/aws-ebs-csi-driver /bin/aws-ebs-csi-driver
COPY --from=debian /sbin/blkid \
                   /sbin/blockdev \
                   /sbin/dumpe2fs \
                   /sbin/resize2fs \
                   /sbin/fsck /sbin/fsck.ext4 /sbin/fsck.ext3 /sbin/fsck.xfs \
                   /sbin/mkfs /sbin/mkfs.ext4 /sbin/mkfs.ext3 /sbin/mkfs.xfs \
                   /sbin/
COPY --from=debian /usr/sbin/xfs_io \
                   /usr/sbin/xfs_growfs \
                   /usr/sbin/
COPY --from=debian /bin/umount /bin/umount
COPY --from=debian /bin/mount /bin/mount
COPY --from=debian ${LIB_DIRECTORY}/libcom_err.so.2 \
                   ${LIB_DIRECTORY}/libc.so.6 \
                   ${LIB_DIRECTORY}/libdevmapper.so.1.02.1 \
                   ${LIB_DIRECTORY}/libdl.so.2 \
                   ${LIB_DIRECTORY}/libe2p.so.2 \
                   ${LIB_DIRECTORY}/libext2fs.so.2 \
                   ${LIB_DIRECTORY}/libm.so.6 \
                   ${LIB_DIRECTORY}/libpthread.so.0 \
                   ${LIB_DIRECTORY}/libselinux.so.1 \
                   ${LIB_DIRECTORY}/libtinfo.so.6 \
                   ${LIB_DIRECTORY}/
COPY --from=debian /usr/${LIB_DIRECTORY}/libblkid.so.1 \
                   /usr/${LIB_DIRECTORY}/libbsd.so.0 \
                   /usr/${LIB_DIRECTORY}/libedit.so.2 \
                   /usr/${LIB_DIRECTORY}/libinih.so.1 \
                   /usr/${LIB_DIRECTORY}/libmd.so.0 \
                   /usr/${LIB_DIRECTORY}/libmount.so.1 \
                   /usr/${LIB_DIRECTORY}/libpcre2-8.so.0 \
                   /usr/${LIB_DIRECTORY}/libudev.so.1 \
                   /usr/${LIB_DIRECTORY}/libuuid.so.1 \
                   /usr/${LIB_DIRECTORY}/
ENTRYPOINT ["/bin/aws-ebs-csi-driver"]
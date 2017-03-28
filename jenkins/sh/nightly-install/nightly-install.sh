#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env OPENZFS_DIRECTORY INSTALL_DEBUG

OPENZFS_DIRECTORY=$(log_must readlink -f "$OPENZFS_DIRECTORY")
log_must test -d "$OPENZFS_DIRECTORY"
log_must cd "$OPENZFS_DIRECTORY"

ONU="${OPENZFS_DIRECTORY}/usr/src/tools/scripts/onu"
REPO="${OPENZFS_DIRECTORY}/packages/i386/nightly"
[[ "$INSTALL_DEBUG" == "yes" ]] || REPO="${REPO}-nd"

log_must sudo "${ONU}" -t "openzfs-nightly" -d "${REPO}"

exit 0

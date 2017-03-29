#!/bin/bash

source ${JENKINS_DIRECTORY}/common.sh

check_env OPENZFS_DIRECTORY INSTALL_DEBUG

DIR=$(dirname ${BASH_SOURCE[0]})

OPENZFS_DIRECTORY=$(log_must readlink -f "$OPENZFS_DIRECTORY")
log_must test -d "$OPENZFS_DIRECTORY"

REPO="${OPENZFS_DIRECTORY}/packages/i386/nightly"
[[ "$INSTALL_DEBUG" == "yes" ]] || REPO="${REPO}-nd"
REPO="$REPO/repo.redist"

for pkg in "pkg:/network/ssh" \
	"pkg:/service/network/ssh" \
	"pkg:/service/network/ftp" \
	"pkg:/service/network/ssh-common" \
	"pkg:/service/network/smtp/sendmail"; do
	log_must pkgrepo -s "$REPO" remove "$pkg"
done

log_must cp /usr/share/distro_const/text_install/text_mode_x86.xml .
log_must chmod 644 text_mode_x86.xml
log_must patch -p1 text_mode_x86.xml <"$DIR/text_mode_x86.xml.patch"
log_must sed -i "s|%%REPO%%|$REPO|" text_mode_x86.xml
log_must sudo distro_const build text_mode_x86.xml

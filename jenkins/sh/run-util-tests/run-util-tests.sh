#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env RUNFILE
log_must sudo /opt/util-tests/bin/utiltest -c $RUNFILE

# vim: tabstop=4 shiftwidth=4 expandtab textwidth=72 colorcolumn=80

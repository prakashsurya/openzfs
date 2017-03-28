#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env RUNFILE
log_must sudo /opt/util-tests/bin/utiltest -c $RUNFILE

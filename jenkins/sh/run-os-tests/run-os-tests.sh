#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env RUNFILE
log_must sudo /opt/os-tests/bin/ostest -c $RUNFILE

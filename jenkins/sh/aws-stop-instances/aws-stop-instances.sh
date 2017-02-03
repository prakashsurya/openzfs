#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh
source ${JENKINS_DIRECTORY}/sh/library/aws.sh

check_env REGION INSTANCE_ID

aws_setup_environment "$REGION"

log_must aws ec2 stop-instances --instance-ids "$INSTANCE_ID"
log_must aws_wait_for_instance_state "$INSTANCE_ID" "stopped"

# vim: tabstop=4 shiftwidth=4 expandtab textwidth=72 colorcolumn=80

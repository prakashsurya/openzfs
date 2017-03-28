#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh
source ${JENKINS_DIRECTORY}/sh/library/aws.sh
source ${JENKINS_DIRECTORY}/sh/library/ssh.sh

check_env REGION INSTANCE_ID REMOTE_DIRECTORY LOCAL_FILE

aws_setup_environment "$REGION"

HOST=$(log_must aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
	| jq -M -r .Reservations[0].Instances[0].PublicIpAddress)

log_must pushd "$JENKINS_DIRECTORY/ansible" >/dev/null
ssh_wait_for inventory.txt playbook.yml
log_must popd >/dev/null

#
# If the directory specified via $REMOTE_DIRECTORY doesn't exist, then the
# download process below will fail. As a result, we check the existence
# of this directory, and proactively fail if it's not found.
#
ssh_log_must test -d "$REMOTE_DIRECTORY"

ssh_fetch_remote_directory "$REMOTE_DIRECTORY" >"$LOCAL_FILE"

# vim: tabstop=4 shiftwidth=4 noexpandtab textwidth=72 colorcolumn=80

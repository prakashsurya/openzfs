#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh
source ${JENKINS_DIRECTORY}/sh/library/vault.sh
source ${JENKINS_DIRECTORY}/sh/library/aws.sh

check_env REGION INSTANCE_ID ROLES WAIT_FOR_SSH

aws_setup_environment "$REGION"

log_must cd "$JENKINS_DIRECTORY/ansible"

HOST=$(log_must aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
	| jq -M -r .Reservations[0].Instances[0].PublicIpAddress)

log_must cat >inventory.txt <<EOF
$HOST ansible_ssh_user=root ansible_ssh_pass=root
EOF

log_must cat >playbook.yml <<EOF
---
EOF

if [[ "$WAIT_FOR_SSH" == "yes" ]]; then
	log_must cat >>playbook.yml <<-EOF
	- hosts: localhost
	  gather_facts: no
	  tasks:
	    - wait_for:
	        host: $HOST
	        port: 22
	        state: started
	        timeout: 1800
	EOF
fi

log_must cat >>playbook.yml <<EOF
- hosts: $HOST
  roles:
EOF

for ROLE in $ROLES; do
	log_must cat >>playbook.yml <<-EOF
	  - $ROLE
	EOF
done

#
# Output the contents of this file to have it logged in the Jenkins job's
# console page, making the contents more accessible which can aid debugging.
#
log_must cat playbook.yml

log_must ansible-playbook -vvvv -i inventory.txt \
	--extra-vars="$EXTRA_VARS" playbook.yml

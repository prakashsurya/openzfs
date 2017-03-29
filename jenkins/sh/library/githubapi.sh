#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh
source ${JENKINS_DIRECTORY}/sh/library/vault.sh

function githubapi_setup_environment() {
	#
	# We need to be careful not to expose the token such that it will
	# end up in the console logs of the jenkins job that will execute
	# this script.
	#
	log_must cat >netrc-file <<EOF
machine api.github.com
  login $(vault_read_github_user)
  password $(vault_read_github_token)
EOF

	#
	# The ruby netrc module will throw an error if the netrc file's
	# permissions are not 600.
	#
	log_must chmod 600 netrc-file
}

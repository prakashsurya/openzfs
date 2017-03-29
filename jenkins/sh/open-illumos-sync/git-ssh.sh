#!/bin/sh

ssh -i "$HOME/.ssh/id_rsa" \
	-o StrictHostKeyChecking=no \
	-o UserKnownHostsFile=/dev/null \
	"$@"

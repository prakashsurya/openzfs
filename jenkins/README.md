OpenZFS Continuous Integration Powered by Jenkins
=================================================

This directory contains all of the source code that powers the automated
builds and testing of OpenZFS GitHub Pull Requests. The following is a
brief explanation of the sub-directories contained, and how their
intended to be used:

  - ansible: This directory contains all of the [Ansible][ansible]
    files that are used to configure the [EC2][ec2] VMs that are
    dynamically generated to execute the build and tests. After the VMs
    are started, they must be configured as Jenkins agents with all of
    the necessary dependencies installed (e.g. compilers, etc); these
    Ansible files enable this configuration.

  - sh: This directory contains various [Bash][bash] scripts that are
    used throughout the build and test cycle. This includes, but is not
    limited to, scripts to perform the following tasks:

      - Create a VM in Amazon's EC2 environment
      - Run Ansible to configure the Amazon EC2 VMs
      - Perform a full "nightly" build of OpenZFS
      - Clone an upgraded VM, in order to run the tests
      - Execute the various regression tests
      - Terminate all VMs after the build and tests complete

[ansible]: https://en.wikipedia.org/wiki/Ansible_(software)
[ec2]: https://en.wikipedia.org/wiki/Amazon_Elastic_Compute_Cloud
[bash]: https://en.wikipedia.org/wiki/Bash_(Unix_shell)

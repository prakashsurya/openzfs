env.REGION = 'us-east-1'
env.BASE_IMAGE_ID = 'ami-e22c92f4'

node('master') {
    stage('checkout, verify, stash') {
        deleteDir()
        checkout scm

        /*
         * We can't allow unpriveledged users from modifying the files in the "jenkins" directory, and then
         * submitting a pull request that would then execute the modified files on the Jenkins master. This
         * would allow a malicious user a way to run arbitary code on the Jenkins master, which could then
         * manipulate our AWS infrastructure, and/or extract secrets (e.g. AWS credentials, etc.) from the
         * vault. The "readTrusted" function used below will cause the build to fail if it detects the file
         * being read was modified, and the user that submitted the PR did not have write access to the
         * repository (to which the PR was opened).
         */
        def files = sh(script: 'find jenkins -type f', encoding: 'UTF-8', returnStdout: true).trim().tokenize('\n')
        for (file in files) {
            readTrusted(file)
        }

        /*
         * When building, we need access to the ".git" directory so that things like "git-describe" will work,
         * which the build systems makes use of. By default, this directory is excluded, so we have to
         * explicitly disable that behavior using the "useDefaultExcludes" parameter. If the ".git" directory
         * was not avaiable later when performing the build, the build will fail.
         */
        stash(name: 'openzfs', useDefaultExcludes: false)

        /*
         * When executing the tests, we only need access to the "jenkins" directory. Thus, we create a second
         * stash such that we can unstash only that directory when running the tests.
         */
        stash(name: 'jenkins', includes: 'jenkins/**')
    }

    try {
        stage('create build instance') {
            env.BUILD_INSTANCE_ID = shscript('aws-run-instances', true, [
                ['REGION', env.REGION],
                ['IMAGE_ID', env.BASE_IMAGE_ID],
                ['INSTANCE_TYPE', 'c4.xlarge'],
                ['ADD_DISKS', 'no']
            ]).trim()
        }

        timeout(time: 4, unit: 'HOURS') {
            stage('configure build instance') {
                if (!env.BUILD_INSTANCE_ID) {
                    error('Empty BUILD_INSTANCE_ID environment variable.')
                }

                shscript('ansible-deploy-roles', false, [
                    ['REGION', env.REGION],
                    ['INSTANCE_ID', env.BUILD_INSTANCE_ID],
                    ['EXTRA_VARS', "jenkins_slave_name=${env.BUILD_INSTANCE_ID} jenkins_master_url=${env.JENKINS_URL}"],
                    ['ROLES', 'openzfs.build-slave openzfs.jenkins-slave'],
                    ['WAIT_FOR_SSH', 'yes']
                ])
            }

            node(env.BUILD_INSTANCE_ID) {
                stage('unstash repository') {
                    unstash('openzfs')
                }

                stage('build') {
                    shscript('nightly-build', false, [
                        ['BUILD_NONDEBUG', 'yes'],
                        ['BUILD_DEBUG', 'yes'],
                        ['RUN_LINT', 'yes']
                    ])
                }

                stage('nits') {
                    shscript('nightly-nits', false, [])
                }

                stage('install') {
                    shscript('nightly-install', false, [
                        ['INSTALL_DEBUG', 'yes']
                    ])
                }
            }
        }

        stage('create image') {
            shscript('aws-stop-instances', false, [
                ['REGION', env.REGION],
                ['INSTANCE_ID', env.BUILD_INSTANCE_ID]
            ])

            env.BUILD_IMAGE_ID = shscript('aws-create-image', true, [
                ['REGION', env.REGION],
                ['INSTANCE_ID', env.BUILD_INSTANCE_ID]
            ]).trim()
        }

        stage('run tests') {
            parallel('run libc-tests': {
                run_test('run-libc-tests', 't2.medium', 2, 'no', [
                    ['RUNFILE', '/opt/libc-tests/runfiles/default.run']
                ])
            }, 'run os-tests': {
                run_test('run-os-tests', 't2.medium', 2, 'no', [
                    ['RUNFILE', '/opt/os-tests/runfiles/default.run']
                ])
            }, 'run util-tests': {
                run_test('run-util-tests', 't2.medium', 2, 'no', [
                    ['RUNFILE', '/opt/util-tests/runfiles/default.run']
                ])
            }, 'run zfs-tests': {
                run_test('run-zfs-tests', 'm4.large', 8, 'yes', [
                    ['RUNFILE', '/opt/zfs-tests/runfiles/delphix.run']
                ])
            }, 'run zloop': {
                run_test('run-zloop', 'm4.large', 4, 'no', [
                    ['ENABLE_WATCHPOINTS', 'no'],
                    ['RUN_TIME', '6000']
                ])
            })
        }
    } finally {
        stage('delete image') {
            if (env.BUILD_INSTANCE_ID) {
                shscript('aws-terminate-instances', false, [
                    ['REGION', env.REGION],
                    ['INSTANCE_ID', env.BUILD_INSTANCE_ID]
                ])
            }

            if (env.BUILD_IMAGE_ID && env.BUILD_IMAGE_ID != env.BASE_IMAGE_ID) {
                shscript('aws-delete-image', false, [
                    ['REGION', env.REGION],
                    ['IMAGE_ID', env.BUILD_IMAGE_ID]
                ])
            }
        }
    }
}

def run_test(script, instance_type, limit, disks, parameters) {
    if (!env.BUILD_IMAGE_ID) {
        error('Empty BUILD_IMAGE_ID environment variable.')
    }

    /*
     * When we run "shscript" below, we need to be careful to ensure that if the scripts are executed in
     * parallel, they don't overwrite the data in the workspace that another script happens to be using.
     *
     * When the scripts are executed without running on a seperate "node", they will end up sharing the same
     * workspace. Thus, if a script is executed in parallel, the two invocations can easily "corrupt" the
     * workspace by each invocation writing to the same file at (more or less) the same time. To workaround
     * this, we use "ws" to ensure a unique workspace is provided for each script that's invoked.
     *
     * Additionally, since "ws" will allocate a new workspace, we then need to "unstash" the openzfs repository,
     * so the underlying shell script is available to be executed by "shscript". Even though the repository was
     * checked out in the beginning of the job, that copy won't be present in the workspace allocated by "ws".
     */
    ws {
        def instance_id = null
        try {
            deleteDir()
            unstash('jenkins')

            instance_id = shscript('aws-run-instances', true, [
                ['REGION', env.REGION],
                ['IMAGE_ID', env.BUILD_IMAGE_ID],
                ['INSTANCE_TYPE', instance_type],
                ['ADD_DISKS', disks]
            ]).trim()

            timeout(time: limit, unit: 'HOURS') {
                if (!instance_id) {
                    error('Unable to create instance.')
                }

                shscript('ansible-deploy-roles', false, [
                    ['REGION', env.REGION],
                    ['INSTANCE_ID', instance_id],
                    ['EXTRA_VARS',
                        "jenkins_slave_name=${instance_id} jenkins_master_url=${env.JENKINS_URL}"],
                    ['ROLES', 'openzfs.build-slave openzfs.jenkins-slave'],
                    ['WAIT_FOR_SSH', 'yes']
                ])

                try {
                    node(instance_id) {
                        unstash('jenkins')
                        shscript(script, false, parameters)
                    }
                } finally {
                    shscript('download-remote-directory', false, [
                        ['REGION', env.REGION],
                        ['INSTANCE_ID', instance_id],
                        ['REMOTE_DIRECTORY', '/var/tmp/test_results'],
                        ['LOCAL_FILE', "${script}.tar.xz"]
                    ])

                    archive(includes: "${script}.tar.xz")

                    /*
                     * The 'run-zloop' script creates a different log file than the other test scripts, so we must
                     * add a special case when running that script.
                     */
                    def remote_file = '/var/tmp/test_results/*/log'
                    if (script == 'run-zloop')
                        remote_file = '/var/tmp/test_results/ztest.out'

                    shscript('download-remote-file', false, [
                        ['REGION', env.REGION],
                        ['INSTANCE_ID', instance_id],
                        ['REMOTE_FILE', '/var/tmp/test_results/*/log'],
                        ['LOCAL_FILE', "${script}.log"]
                    ])

                    archive(includes: "${script}.log")
                }
            }
        } finally {
            if (instance_id) {
                shscript('aws-terminate-instances', false, [
                    ['REGION', env.REGION],
                    ['INSTANCE_ID', instance_id]
                ])
            }
        }
    }
}

def shscript(script, returnStdout, parameters) {
    def ret = null
    def environment = [
        "OPENZFS_DIRECTORY=.",
        "JENKINS_DIRECTORY=./jenkins"
    ]

    /*
     * It'd be cleaner to use a map datastructure for the parameters object, but iterating over a map in the Jenkins
     * pipeline plugin does not work properly. Thus, we're forced to use a two dimensional array and a C-sytle loop.
     */
    for (def i = 0; i < parameters.size(); i++) {
        def entry = parameters.get(i)
        def key = entry.get(0)
        def value = entry.get(1)
        environment.add("${key}=${value}")
    }

    withEnv(environment) {
        wrap([$class: 'AnsiColorBuildWrapper']) {
            ret = sh(encoding: 'UTF-8', returnStatus: false, returnStdout: returnStdout,
                script: "${JENKINS_DIRECTORY}/sh/${script}/${script}.sh")
        }
    }

    return ret
}

// vim: syntax=groovy tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

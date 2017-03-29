currentBuild.displayName = "#${env.BUILD_NUMBER} ${OPENZFS_REPOSITORY} ${OPENZFS_BRANCH}"

node('master') {
    def misc = null

    stage('checkout, stash repository') {
        checkout([$class: 'GitSCM', changelog: false, poll: false,
                  userRemoteConfigs: [[name: 'origin', url: "https://github.com/${OPENZFS_REPOSITORY}"]],
                  branches: [[name: OPENZFS_BRANCH]]])
        stash(name: 'openzfs', useDefaultExcludes: false)
        misc = load('jenkins/pipelines/miscellaneous.groovy')
    }

    try {
        stage('create instance') {
            env.INSTANCE_ID = misc.shscript('aws-run-instances', true, [
                ['REGION', env.REGION],
                ['IMAGE_ID', env.BASE_IMAGE_ID],
                ['INSTANCE_TYPE', 'c4.xlarge'],
                ['ADD_DISKS', 'no']
            ]).trim()
        }

        stage('configure instance') {
            if (!env.INSTANCE_ID) {
                error('Empty INSTANCE_ID environment variable.')
            }

            misc.shscript('ansible-deploy-roles', false, [
                ['REGION', env.REGION],
                ['INSTANCE_ID', env.INSTANCE_ID],
                ['ROLES', 'openzfs.build-slave openzfs.jenkins-slave'],
                ['WAIT_FOR_SSH', 'yes']
            ])
        }

        node(env.INSTANCE_ID) {
            stage('unstash repository') {
                unstash(name: 'openzfs')
            }

            stage('build repository') {
                misc.shscript('nightly-build', false, [
                    ['BUILD_NONDEBUG', 'yes'],
                    ['BUILD_DEBUG', 'no'],
                    ['RUN_LINT', 'no']
                ])
            }

            stage('build install media') {
                misc.shscript('nightly-iso-build', false, [
                    ['INSTALL_DEBUG', 'no']
                ])
            }
        }

        stage('archive install media') {
            misc.shscript('download-remote-directory', false, [
                ['REGION', env.REGION],
                ['INSTANCE_ID', instance_id],
                ['REMOTE_DIRECTORY', env.MEDIA_DIRECTORY],
                ['LOCAL_FILE', "install-media.tar.xz"]
            ])

            archive(includes: "${script}.tar.xz")
        }
    } finally {
        if (env.INSTANCE_ID) {
            misc.shscript('aws-terminate-instances', false, [
                ['REGION', env.REGION],
                ['INSTANCE_ID', env.INSTANCE_ID]
            ])
        }
    }
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

currentBuild.displayName = "#${env.BUILD_NUMBER} ${env.OPENZFS_REPOSITORY}"

node('master') {
    def misc = null
    stage('setup') {
        checkout([$class: 'GitSCM', changelog: false, poll: false,
                  userRemoteConfigs: [[name: 'origin', url: "https://github.com/${OPENZFS_REPOSITORY}"]],
                  branches: [[name: OPENZFS_BRANCH]]])
        misc = load('jenkins/pipelines/library/miscellaneous.groovy')
    }

    stage('send mail') {
        misc.shscript('send-illumos-mail', false, [
            ['REPOSITORY', OPENZFS_REPOSITORY],
        ])
    }
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

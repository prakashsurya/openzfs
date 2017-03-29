pipelineJob('build-install-media') {
    quietPeriod(0)
    concurrentBuild(true)

    parameters {
        stringParam('OPENZFS_REPOSITORY', System.getenv('OPENZFS_REPOSITORY'))
        stringParam('OPENZFS_BRANCH', System.getenv('OPENZFS_BRANCH'))
        stringParam('OPENZFS_DIRECTORY', 'openzfs')
    }

    environmentVariables {
        env('REGION', 'us-east-1')
        env('BASE_IMAGE_ID', 'ami-e22c92f4')
        env('MEDIA_DIRECTORY', '/rpool/dc/media')
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/pipelines/build_install_media.groovy'))
            sandbox()
        }
    }
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

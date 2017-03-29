pipelineJob('open-illumos-sync') {
    quietPeriod(0)
    concurrentBuild(false)

    if (System.getenv('OPENZFSCI_PRODUCTION').toBoolean()) {
        triggers {
            scm('@weekly')
        }
    }

    environmentVariables {
        // This must be set to "origin" due to the requirements of the "hub" command.
        env('OPENZFS_REMOTE', 'origin')
        env('OPENZFS_REPOSITORY', System.getenv('OPENZFS_REPOSITORY'))
        env('OPENZFS_BRANCH', System.getenv('OPENZFS_BRANCH'))

        env('ILLUMOS_REMOTE', 'illumos')
        env('ILLUMOS_REPOSITORY', 'illumos/illumos-gate')
        env('ILLUMOS_BRANCH', 'master')
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/pipelines/open_illumos_sync.groovy'))
            sandbox()
        }
    }
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

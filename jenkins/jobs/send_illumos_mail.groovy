pipelineJob('send-illumos-mail') {
    quietPeriod(0)
    concurrentBuild(false)

    if (System.getenv('OPENZFSCI_PRODUCTION').toBoolean()) {
        triggers {
            cron('H/5 * * * *')
        }
    }

    environmentVariables {
        env('OPENZFS_REPOSITORY', System.getenv('OPENZFS_REPOSITORY'))
        env('OPENZFS_BRANCH', System.getenv('OPENZFS_BRANCH'))
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/pipelines/send_illumos_mail.groovy'))
            sandbox()
        }
    }
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

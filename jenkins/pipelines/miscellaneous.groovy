def shscript(script, returnStdout, parameters) {
    def ret = null
    def environment = [
        "OPENZFS_DIRECTORY=.",
        "JENKINS_DIRECTORY=./jenkins",
        "JENKINS_URL=${env.JENKINS_URL}"
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

return this;

// vim: syntax=groovy tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

node('master') {
    stage('checkout and stash') {
        checkout scm
        stash(name: 'illumos', includes: '**', useDefaultExcludes: false)
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120

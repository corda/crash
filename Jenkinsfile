#!groovy

/**
 * Kill already started job.
 * Assume new commit takes precendence and results from previous
 * unfinished builds are not required.
 * This feature doesn't play well with disableConcurrentBuilds() option
 */
@Library('corda-shared-build-pipeline-steps')
import static com.r3.build.BuildControl.killAllExistingBuildsForJob

killAllExistingBuildsForJob(env.JOB_NAME, env.BUILD_NUMBER.toInteger())

pipeline {
    agent { label 'standard' }

    options {
        timestamps()
        timeout(time: 1, unit: 'HOURS')
        buildDiscarder(logRotator(daysToKeepStr: '14', artifactDaysToKeepStr: '14'))
    }

    tools {
        maven "maven"
    }

    parameters {
        booleanParam(name: "TESTS",
                description: "Skip tests",
                defaultValue: false)
    }

    environment {
        ARTIFACTORY_CREDENTIALS = credentials('artifactory-credentials')
        CORDA_ARTIFACTORY_USERNAME = "${env.ARTIFACTORY_CREDENTIALS_USR}"
        CORDA_ARTIFACTORY_PASSWORD = "${env.ARTIFACTORY_CREDENTIALS_PSW}"
        JAVA_HOME = "/usr/lib/jvm/java-1.8.0-amazon-corretto"
        SNYK_TOKEN = credentials('c4-os-snyk-api-token-secret')
    }

    stages {

        stage('Build ') {
            steps {
                sh "mvn -B install -DskipTests"

            }
        }

        stage('Snyk Security') {
            when {
                expression { return isMainBranch() }
            }
            steps {
                snykSecurityScan(env.SNYK_TOKEN, "--maven-aggregate-project --configuration-matching='^runtimeClasspath\$' --prune-repeated-subdependencies --debug --target-reference='${env.BRANCH_NAME}' --project-tags=Branch='${env.BRANCH_NAME.replaceAll("[^0-9|a-z|A-Z]+","_")}' ", false, true)
            }
        }
        
        stage('Test ') {
            when {
                expression { !params.TESTS }
            }
            steps {
                sh "mvn -B test"
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: '**/target/surefire-reports/**/TEST-*.xml'
                    archiveArtifacts artifacts: '**/target/surefire-reports/**/TEST-*.xml', fingerprint: true
                }
            }
        }

        stage('Deploy SNAPSHOT to artifactory') {
            when {
                expression { return isMainBranch() }
            }
            steps {
                sh "mvn deploy -B -s settings.xml -DskipTests"
            }
        }

        stage('Deploy Release to artifactory') {
            when {
                expression { return isReleaseTag() }
            }
            steps {
                sh "mvn deploy -B -s settings.xml -DskipTests"
            }
        }
    }
}


def isReleaseTag() {
    return (env.TAG_NAME =~ /^release-.*$/)
}

def isMainBranch() {
    return (env.BRANCH_NAME =~ /^master$/)
}

pipeline {
    agent any

    environment {
        SAST_REPORT = "results/sast_output.txt"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Go and Run SAST Tool') {
            steps {
                sh '''
                    mkdir -p results
                    go run file_iterator.go --input ./testcode/ > results/${SAST_REPORT}
                '''
            }
        }

        stage('Check Vulnerabilities') {
            steps {
                script {
                    def found = sh(script: "grep -i 'vulnerability' results/${SAST_REPORT}", returnStatus: true)
                    if (found == 0) {
                        currentBuild.result = 'UNSTABLE'
                        env.SHOULD_EMAIL = "true"
                    } else {
                        env.SHOULD_EMAIL = "false"
                    }
                }
            }
        }
    }

    post {
        unstable {
            script {
                if (env.SHOULD_EMAIL == "true") {
                    emailext (
                        subject: "🚨 SAST Alert - Vulnerabilities Found",
                        body: "Hello,\n\nVulnerabilities were found in the latest scan.\n\nCheck the attached report.\n\nThanks,\nSAST Bot",
                        to: "maacyaswanth@gmail.com",
                        attachmentsPattern: "${SAST_REPORT}"
                    )
                }
            }
        }
    }
}

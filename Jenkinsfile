pipeline {
    agent any

    environment {
        SAST_REPORT = "results/report.txt"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Go and Run SAST Tool') {
            steps {
                bat 'go version'
                bat 'go run file_iterator.go --input ./testcode/'
            }
        }

        stage('Check Vulnerabilities') {
            steps {
                 bat 'dir results' 
                script {
                    // Using bat and checking exit code manually
                    def result = bat(
                        script: 'findstr /i "vulnerability" results\\report.txt',
                        returnStatus: true
                    )
                    if (result == 0) {
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
                        attachmentsPattern: "${report}"
                    )
                }
            }
        }
    }
}

#!/bin/bash
## Author: Dang Thanh Phat
## Email: thanhphatit95@gmail.com
## Web/blogs: www.itblognote.com
## Description:
##      Path working: environments/<env>/<service-provider>/<service-identifier>/..
##
## TODO:
##      - Check if chartname exists in repo
##      - Check git log if find files changed, to reduce time
##      - Check helm plugin diff: helm plugin install https://github.com/databus23/helm-diff
##      - Check if we had delete plag

#### GLOBAL SETTING SHELL
set -o pipefail
set -e

####################
# GLOBAL VARIABLES #
####################

#### VARIABLES

ACTION="${1:-plan}"
METHOD="${2:-http}" # Valid value: http / s3 / acr
DEBUG="${3:-debug}"

SCAN_ALL_FILES="${SCAN_ALL_FILES:-false}"

HTTP_USER="${HTTP_USER:-none}"
HTTP_PASSWORD="${HTTP_PASSWORD:-none}"

HELM_PRIVATE_REPO_NAME="${HELM_PRIVATE_REPO_NAME:-helm-charts}"
S3_BUCKET_NAME="${S3_BUCKET_NAME:-none}" #set this variable if you use S3 storage for Helm Charts

ACR_NAME="${ACR_NAME:-none}" # Set this variable if you use ACR for Helm Charts
ACR_ARTIFACT_NAME="oci://${ACR_NAME}.azurecr.io/helm"

BRANCH_CURRENT="main"
BRANCH_MAIN="main"

HELM_LIST_MAX_LIMIT="--max 2605"

TMPFILE_LIST_HL=$(mktemp /tmp/tempfile-list-yaml-XXXXXXXX)
TMPFILE_LIST_HL_DIRS="${TMPFILE_LIST_HL}.parent-dirs"
TMPFILE_LIST_PROVIDERS="${TMPFILE_LIST_HL}.providers"
TMPFILE_LISTFILES_COMPARE=$(mktemp /tmp/tempfile-list-yaml-compare-branch-XXXXXXXX)

### Used with echo have flag -e
RLC="\033[1;31m"    ## Use redlight color
GC="\033[0;32m"     ## Use green color
YC="\033[0;33m"     ## Use yellow color
BC="\033[0;34m"     ## Use blue color
EC="\033[0m"        ## End color with no color

#### FUNCTIONS

function check_var(){
    local VAR_LIST=(${1})

    for var in ${VAR_LIST[@]}; do
        if [[ -z "$(eval echo $(echo $`eval echo "${var}"`))" ]];then
            echo -e "${YC}[CAUTIONS] Variable ${var} not found!"
            exit 1
        fi
    done
}

function pre_check_dependencies(){
    ## All tools used in this script
    local TOOLS_LIST=(${1})

    for tools in ${TOOLS_LIST[@]}; do
        # If not found tools => exit
        if [[ ! $(command -v ${tools}) ]];then
cat << ALERTS
[x] Not found tool [${tools}] on machine.

Exit.
ALERTS
            exit 1
        fi
    done

    #### Example: pre_check_dependencies "helm" 
}

function check_plugin(){
    local COMMAND_PLUGIN_LIST="${1}"
    local PLUGIN_LIST=(${2})

    local TOOLS_NAME="$(echo "${COMMAND_PLUGIN_LIST}" | awk '{print $1}')"

    for plugin in ${PLUGIN_LIST[@]}; do
        # If not found tools => exit
        if [[ ! $(${COMMAND_PLUGIN_LIST} | grep -i "^${plugin}") ]];then
cat << ALERTS
[x] Not found this ${TOOLS_NAME} plugin [${plugin}] on machine.

Exit.
ALERTS
            exit 1
        fi
    done

    #### Example: check_plugin "cm-push diff s3" 
}

function compare_versions() {
    local VERSION_01=${1}
    local VERSION_02=${2}

    if [[ ${VERSION_01} == ${VERSION_02} ]]; then
        echo "equal"
    else
        local IFS=.
        local ver1=(${VERSION_01})
        local ver2=(${VERSION_02})

        local len=${#ver1[@]}
        for ((i=0; i<len; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi

        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            echo "less"
            return
        fi

        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            echo "greater"
            return
        fi
        done

        echo "equal"
    fi
}

function about(){
cat <<ABOUT

*********************************************************
* Author: DANG THANH PHAT                               *
* Email: thanhphat@itblognote.com                       *
* Blog: www.itblognote.com                              *
* Version: 2.2                                          *
* Purpose: Tools to deploy helm on k8s with templates.  *
*********************************************************

Use --help or -h to check syntax, please !

ABOUT
    exit 1
}

function help(){
cat <<HELP

Usage: k8s-templates-helm [options...] [method...] [debug...]

[*] OPTIONS:
    -h, --help            Show help
    -v, --version         Show info and version
    apply                 Start deploy helm templates to k8s with your method ACR, HTTP, S3,...
    plan                  (This is default value) - plan will have people know what will happen

[*] METHOD:
    http                  You can create a server helm with 'chartmuseum' to get helm and deploy
    s3                    Get helm from S3 Bucket service AWS to deploy
    acr                   Get helm from ACR service Azure to deploy

[*] DEBUG: (Support for DevOps code)
    debug                 Add tag --wait for helm charts templates when deploy

HELP
    exit 1
}

# Init/Pre-check
function init() {
    if [[ ! -f ${TMPFILE_LIST_HL} ]];then
        touch ${TMPFILE_LIST_HL}
    fi

    if [[ ! -f ${TMPFILE_LIST_PROVIDERS} ]];then
        touch ${TMPFILE_LIST_PROVIDERS}
    fi

    if [[ ! -f ${TMPFILE_LIST_HL_DIRS} ]];then
        touch ${TMPFILE_LIST_HL_DIRS}
    fi
}

# Cleanup
function cleanup() {
    # Delete tempfile
    if [[ -f ${TMPFILE_LIST_HL} ]];then
        rm -f ${TMPFILE_LIST_HL}
    fi

    if [[ -f ${TMPFILE_LIST_PROVIDERS} ]];then
        rm -f ${TMPFILE_LIST_PROVIDERS}
    fi

    if [[ -f ${TMPFILE_LIST_HL_DIRS} ]];then
        rm -f ${TMPFILE_LIST_HL_DIRS}
    fi

    if [[ "${METHOD}" == "s3" ]];then
        unset AWS_PROFILE
    fi
}

function cmdstatus(){
    local _STATUS="$1"
    local _MESSAGE="$2"

    if [[ "${_STATUS}" -gt 0 ]];then
        echo "[x] ${_MESSAGE}"
        exit 1
    else
        return 0
    fi
}

function pre_checking()
{
    # What is our ACTION & METHOD
    echo "[+] ACTION: ${ACTION}"
    echo "[+] METHOD: ${METHOD}"
    
    local HELM_VERSION_CURRENT=$(helm version --short --client 2>/dev/null | awk -F'+' '{print $1}' | awk -F'v' '{print $2}')
    local HELM_VERSION_LIMMIT="3.8.0"

    local RESULT_COMPARE_HELM_VERSION=$(compare_versions "${HELM_VERSION_CURRENT}" "${HELM_VERSION_LIMMIT}")

    if [[ ${RESULT_COMPARE_HELM_VERSION} == "less" ]];then
        echo -e "${YC}[WARNING] Because helm version current less than 3.8.0, so we will add variable [HELM_EXPERIMENTAL_OCI=1]"
        export HELM_EXPERIMENTAL_OCI=1
    fi

    # Check if we miss credentials for AWS S3 Plugin
    if [[ "${METHOD}" == "s3" ]];then
        local FLAG_FOUND_AWS_CREDS="false"

        # We need to check available AWS Credentials
        if [[ "$(env | grep -i AWS_PROFILE | awk -F'=' '{print $2}')" != "" ]];then
            FLAG_FOUND_AWS_CREDS="true"
        elif [[ "$(env | grep -i DEFAULT_AWS_PROFILE | awk -F'=' '{print $2}')" != "" ]];then
            FLAG_FOUND_AWS_CREDS="true"
        elif [[ "$(env | grep -wE "AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_DEFAULT_REGION" | wc -l | tr -d ' ')" == "3" ]];then
            FLAG_FOUND_AWS_CREDS="true"
        fi

        if [[ "${FLAG_FOUND_AWS_CREDS}" == "false" ]];then
            echo ""
            echo -e "${YC}[x] CHECKING: cannot find AWS Credentials when you want to use Helm S3 Plugin"
            exit 1
        fi

        # We need to check plugin S3 Helm
        if [[ ! "$(helm plugin list | grep -i "^s3")" ]];then
            echo ""
            echo -e "${YC}[x] CHECKING: cannot find Helm S3 Plugin to use S3 Method"
            exit 1
        fi

        # Check if we get S3 Bucket Environment
        if [[ ! $(echo "${S3_BUCKET_NAME}" | grep -i "^s3://" ) || "${S3_BUCKET_NAME}" == "none" ]];then
            echo ""
            echo -e "${YC}[x] CHECKING: cannot find Environment Variable [S3_BUCKET_NAME]"
            exit 1
        fi

    elif [[ "${METHOD}" == "http" ]];then
        # Check if we miss credentials for http with cregs
        FLAG_FOUND_HTTP_CREDS="false"

        if [[ ${HTTP_USER} != "none" && ${HTTP_PASSWORD} != "none" ]];then
            FLAG_FOUND_HTTP_CREDS="true"
        fi

        if [[ "$(env | grep -i "HELM_HOSTED_REPO_URL" | awk -F'=' '{print $2}')" == "" ]];then
            echo ""
            echo -e "${YC}[x] CHECKING: cannot find env variable [HELM_HOSTED_REPO_URL] when you want to use Helm authenticate HTTP Web App"
            exit 1
        fi 

    elif [[ "${METHOD}" == "acr" ]];then
        # Check if we miss credentials for http with cregs
        FLAG_FOUND_AZ_CREDS="false"

        if [[ ${AZ_USER} != "" && ${AZ_PASSWORD} != "" ]];then
            FLAG_FOUND_AZ_CREDS="true"
        fi

        if [[ "${FLAG_FOUND_AZ_CREDS}" == "false" ]];then
            echo ""
            echo -e "${YC}[x] CHECKING: cannot find AZ Credentials when you want to use Helm Azure ACR"
            exit 1
        fi

        # Check if we get ACR name Environment
        if [[ ! $(echo "${ACR_ARTIFACT_NAME}" | grep -i "^oci://" ) ]];then
            echo ""
            echo -e "${YC}[x] CHECKING: cannot find Environment Variable [ACR_ARTIFACT_NAME]"
            exit 1
        fi
    fi
}

function connect_helm_repo() {
    echo "------------------------------------"
    echo "|   HELM CHART REMOTE REPOSITORY   |"
    echo "------------------------------------"

    # Add Private Helm Repository
    echo "[+] Connect Private Helm Repository: ${HELM_PRIVATE_REPO_NAME}"
    if [[ $(helm repo list 2> /dev/null | grep -i ${HELM_PRIVATE_REPO_NAME} | awk '{print $1}') == ${HELM_PRIVATE_REPO_NAME} ]];then
        # Remove current setting Helm Repo to add new
        helm repo remove ${HELM_PRIVATE_REPO_NAME} 2> /dev/null
    fi

    if [[ "${METHOD}" == "s3" ]];then
        # Helm S3 Bucket
        # Get AWS Credentials
        aws configure set --profile ${HELM_PRIVATE_REPO_NAME} region ${HELM_AWS_REGION}
        aws configure set --profile ${HELM_PRIVATE_REPO_NAME} aws_access_key_id ${HELM_AWS_ACCESS_KEY}
        aws configure set --profile ${HELM_PRIVATE_REPO_NAME} aws_secret_access_key ${HELM_AWS_SECRET_KEY}

        export AWS_PROFILE="${HELM_PRIVATE_REPO_NAME}"
        # Connect to Helm Chart Service with S3 Plugin - S3 Bucket AWS
        helm repo add ${HELM_PRIVATE_REPO_NAME} ${S3_BUCKET_NAME}

    elif [[ "${METHOD}" == "acr" ]];then
        # Connect to Helm Chart Service with ACR Method
        helm repo add ${HELM_PRIVATE_REPO_NAME} https://${ACR_NAME}.azurecr.io/helm/v1/repo --username ${AZ_USER} --password ${AZ_PASSWORD}
        helm registry login ${ACR_NAME}.azurecr.io --username ${AZ_USER} --password ${AZ_PASSWORD}

    elif [[ "${METHOD}" == "http" ]];then
        if [[ ${HTTP_USER} == "none" && ${HTTP_PASSWORD} == "none" ]];then
            # Connect to Helm Chart Service with Web HTTP Method
            helm repo add ${HELM_PRIVATE_REPO_NAME} ${HELM_HOSTED_REPO_URL}
        else
            helm repo add ${HELM_PRIVATE_REPO_NAME} ${HELM_HOSTED_REPO_URL} --username ${HTTP_USER} --password ${HTTP_PASSWORD}
        fi

    fi

    # Update list helm chart repositories
    helm repo update

    # List active Helm Repositories
    echo ""
    echo "[+] List active Helm Chart Repositories"
    helm repo list

    echo ""
    echo "[+] List active Charts in Helm Chart Repository: ${HELM_PRIVATE_REPO_NAME}"
    helm search repo ${HELM_PRIVATE_REPO_NAME}
}

function generate_aws_credentials(){
    # This scripts is used to login multiple aws profile credentials
    echo ""
    echo "-------------------------------------"
    echo "|   AWS PROFILE CREDENTIALS SETUP   |"
    echo "-------------------------------------"

    echo "[*] AWS Credentials Setup"

    local TMPFILE=$(mktemp /tmp/tempfile-XXXXXXXX)
    local TMPDIR_AWS_LOGIN=$(mktemp -d /tmp/aws-credentials-login-XXXXXX)

    # Cleanup
    rm -f "${TMPDIR_AWS_LOGIN}/*"

    # Read each file metadata.conf to get IAM Profile
    echo "[*] Development Status: $DEV_STATUS"
    echo "[*] Staging Status: $STAG_STATUS"
    echo "[*] Production Status: $PROD_STATUS"
    for metafile in `find environments/ -type f -iname "metadata.conf"`
    do
        # if found file metadata.conf has attribute: service_provider: aws
        # means we have config for aws service
        SERVICE_PROVIDER=$(grep "service_provider" ${metafile} | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_ENVIRONMENT=$(grep "environment" ${metafile} | awk -F':' '{print $2}' | tr -d ' ')
        

        if [[ "${SERVICE_PROVIDER}" == "aws" ]];then
            # e.g aws_profile: <env>-eks-deployment
            if [ $DEV_STATUS == "true" ] && [ ${SERVICE_ENVIRONMENT} == "development" ];then
                echo "${SERVICE_ENVIRONMENT}" >> ${TMPDIR_AWS_LOGIN}/environment
            elif [ $STAG_STATUS == "true" ] && [ ${SERVICE_ENVIRONMENT} == "staging" ];then
                echo "${SERVICE_ENVIRONMENT}" >> ${TMPDIR_AWS_LOGIN}/environment
            elif [ $PROD_STATUS == "true" ] && [ ${SERVICE_ENVIRONMENT} == "production" ];then
                echo "${SERVICE_ENVIRONMENT}" >> ${TMPDIR_AWS_LOGIN}/environment
            fi
        fi
    done

    # Uniq environment for aws infra
    cat ${TMPDIR_AWS_LOGIN}/environment | sort | uniq > ${TMPDIR_AWS_LOGIN}/environment.tmp
    rm -f ${TMPDIR_AWS_LOGIN}/environment
    mv ${TMPDIR_AWS_LOGIN}/environment.tmp ${TMPDIR_AWS_LOGIN}/environment

    # Get credentials for each env
    echo ""
    if [[ "$(cat ${TMPDIR_AWS_LOGIN}/environment | wc -l | tr -d ' ')" -gt 0 ]];then
        while read env
        do
            echo "[+] Environment: ${env}"

            if [[ "${env}" == "development" || "${env}" == "dev" || "${env}" == "develop" ]];then
                # Check env
                if [[ ! "$(env | grep -i "DEV_AWS_ACCESS_KEY_ID")" ]];then
                    echo "[x] Cannot find ENV VAR: DEV_AWS_ACCESS_KEY_ID"
                    exit 1
                fi

                if [[ ! "$(env | grep -i "DEV_AWS_SECRET_ACCESS_KEY")" ]];then
                    echo "[x] Cannot find ENV VAR: DEV_AWS_SECRET_ACCESS_KEY"
                    exit 1
                fi

                AWS_ACCESS_KEY_ID="${DEV_AWS_ACCESS_KEY_ID}"
                AWS_SECRET_ACCESS_KEY="${DEV_AWS_SECRET_ACCESS_KEY}"
                AWS_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"

            elif [[ "${env}" == "staging" || "${env}" == "stg" ]];then
                # Check env
                if [[ ! "$(env | grep -i "STG_AWS_ACCESS_KEY_ID")" ]];then
                    echo "[x] Cannot find ENV VAR: STG_AWS_ACCESS_KEY_ID"
                    exit 1
                fi

                if [[ ! "$(env | grep -i "STG_AWS_SECRET_ACCESS_KEY")" ]];then
                    echo "[x] Cannot find ENV VAR: STG_AWS_SECRET_ACCESS_KEY"
                    exit 1
                fi

                AWS_ACCESS_KEY_ID="${STG_AWS_ACCESS_KEY_ID}"
                AWS_SECRET_ACCESS_KEY="${STG_AWS_SECRET_ACCESS_KEY}"
                AWS_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"

            elif [[ "${env}" == "production" || "${env}" == "prod" || "${env}" == "prd"  ]];then
                # Check env
                if [[ ! "$(env | grep -i "PROD_AWS_ACCESS_KEY_ID")" ]];then
                    echo "[x] Cannot find ENV VAR: PROD_AWS_ACCESS_KEY_ID"
                    exit 1
                fi

                if [[ ! "$(env | grep -i "PROD_AWS_SECRET_ACCESS_KEY")" ]];then
                    echo "[x] Cannot find ENV VAR: PROD_AWS_SECRET_ACCESS_KEY"
                    exit 1
                fi

                AWS_ACCESS_KEY_ID="${PROD_AWS_ACCESS_KEY_ID}"
                AWS_SECRET_ACCESS_KEY="${PROD_AWS_SECRET_ACCESS_KEY}"
                AWS_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"

            fi

            # Configure AWS Profile for env
            AWS_ENV_IAM_PROFILE="${env}-eks-deployment"
            aws configure set --profile ${AWS_ENV_IAM_PROFILE} region ${AWS_REGION}
            aws configure set --profile ${AWS_ENV_IAM_PROFILE} aws_access_key_id ${AWS_ACCESS_KEY_ID}
            aws configure set --profile ${AWS_ENV_IAM_PROFILE} aws_secret_access_key ${AWS_SECRET_ACCESS_KEY}

            AWS_CALLER_IDENTITY=$(aws sts get-caller-identity --profile ${AWS_ENV_IAM_PROFILE} --output text)
            if [[ ! $(echo $AWS_CALLER_IDENTITY | grep -Ei "stg|staging|prod|prd|dev|production|development|develop" ) ]];then
                echo "[x] Verify: AWS Result from [sts get-caller-identity] does not match env"
                echo "[-] Result: ${AWS_CALLER_IDENTITY}"
                exit 1
            fi

        done < ${TMPDIR_AWS_LOGIN}/environment
    else
        echo "[x] Do not find any configuration for AWS Environment Infra"
    fi
}

function kubernetes_auth_login() {
    local _SERVICE_PROVIDER="$1"
    local _SERVICE_TYPE="$2"
    local _SERVICE_IDENTIFIER="$3"
    local _SERVICE_CONTEXT="$4"
    local _SERVICE_ENVIRONMENT="$5"

    # Banner
    echo "[*] Kubernetes Authentication Login Process"

    # Check args
    if [[ -z ${_SERVICE_PROVIDER} ]];then
        echo "[x] Cannot find SERVICE_PROVIDER: $_SERVICE_PROVIDER"
        exit 1
    fi

    if [[ -z ${_SERVICE_TYPE} ]];then
        echo "[x] Cannot find SERVICE_TYPE: $_SERVICE_TYPE"
        exit 1
    fi

    if [[ -z ${_SERVICE_IDENTIFIER} ]];then
        echo "[x] Cannot find SERVICE_IDENTIFIER: $_SERVICE_IDENTIFIER"
        exit 1
    fi

    if [[ -z ${_SERVICE_CONTEXT} ]];then
        echo "[x] Cannot find SERVICE_CONTEXT: $_SERVICE_CONTEXT"
        exit 1
    fi

    [ -d ${HOME}/.kube ] && rm -rf ${HOME}/.kube
    mkdir ${HOME}/.kube

    # Proceed Kubernetes Authentication Login
    if [[ "${_SERVICE_PROVIDER}" == "digital-ocean" ]];then
        echo "****************************"
        echo "*       DIGITAL OCEAN      *"
        echo "****************************"
        echo "[-] Digital Ocean: Authenticating api with TOKEN"

        pre_check_dependencies "doctl"
        # We need to hide AccessToken when this script show it in terminal output
        doctl auth init --access-token ${DIGITAL_OCEAN_TOKEN} 1> /dev/null
        local _status_doctl_auth="$?"
        if [[ ${_status_doctl_auth} -eq 0 ]];then
            echo "[-] Status login: successful"
        else
            echo "[-] Status login: failed"
            exit 1
        fi

        echo "[-] Digital Ocean: get kubeconfig for kubernetes cluster [$_SERVICE_IDENTIFIER]"
        doctl kubernetes cluster kubeconfig save ${_SERVICE_IDENTIFIER}

        echo "[-] Kubectl config current-contenxt information: "
        kubectl config current-context

    elif [[ "${_SERVICE_PROVIDER}" == "vng-cloud" && "${_SERVICE_TYPE}" == "kubernetes" ]];then
        echo "**************************"
        echo "*        VNG CLOUD       *"
        echo "**************************"
        echo "[-] VNG Cloud: Authenticating api with Configfile"
        echo ""
        [ -f $HOME/.kube/config ] && cp ./config $HOME/.kube/config || echo "File does not exist"

        echo "[-] Kubectl config current-contenxt information: "
        kubectl config current-context

    elif [[ "${_SERVICE_PROVIDER}" == "aws" && "${_SERVICE_TYPE}" == "eks" ]];then
        generate_aws_credentials
        echo "[-] EKS: authenticate and generate kubeconfig with IAM Authenticator AWS Profile [${_SERVICE_IDENTIFIER}]"

        AWS_ENV_IAM_PROFILE="${_SERVICE_ENVIRONMENT}-eks-deployment"
        AWS_ACCOUNT_ID=$(aws sts get-caller-identity --profile ${AWS_ENV_IAM_PROFILE} --output text  | awk '{print $1}' | tr -d ' ')
        EKS_CLUSTER_ASSUME_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/role-eks-deployment-${_SERVICE_IDENTIFIER}"

        # Update kubeconfig
        FAILED_MSG="Cannot generate kubeconfig about EKS Cluster ${_SERVICE_IDENTIFIER}. Exit."
        aws eks update-kubeconfig \
            --name ${_SERVICE_IDENTIFIER} \
            --region ap-southeast-1 \
            --profile ${AWS_ENV_IAM_PROFILE} \
            --role-arn ${EKS_CLUSTER_ASSUME_ROLE_ARN}

        cmdstatus $? "${FAILED_MSG}"
        chmod go-r ~/.kube/config

        echo "[-] EKS: kubectl config current-contenxt information"
        kubectl config current-context

    elif [[ "${_SERVICE_PROVIDER}" == "azure" && "${_SERVICE_TYPE}" == "aks" ]];then
        echo "****************************"
        echo "*        AZURE CLOUD       *"
        echo "****************************"
        echo "[-] Azure: Authenticating api with Configfile"
        echo ""
        
        curl -u ${DEVOPS_ID}:${DEVOPS_TOKEN} -o ${HOME}/.kube/config https://dev.azure.com/${AZ_DEVOPS_NAME}/${AZ_DEVOPS_PROJECT}/_apis/git/repositories/${AZ_DEVOPS_REPOS}/Items?path=/${PATH_FILE_CONFIG}&version=master&download=true &
        wait

        kubectl config use-context ${_SERVICE_CONTEXT}

        echo "[-] Kubectl config current-contenxt information: "
        kubectl config current-context
    fi

    echo ""
}

function compare_main_and_non_main_branch()
{
    # BRANCH_CURRENT="$(git rev-parse --abbrev-ref HEAD)"

    # If current_branch is not main/master
    # We compare between master/main and this branch
    if [[ "${BRANCH_CURRENT}" != "${BRANCH_MAIN}" ]];then
        echo "[+] Compare branch: ${BRANCH_MAIN}...${BRANCH_CURRENT}"
        git diff --diff-filter=ACMRTUXB --name-only ${BRANCH_MAIN}...${BRANCH_CURRENT} | grep -i "^environments" | grep -i "yaml$" > ${TMPFILE_LISTFILES_COMPARE}

        # Check directory have delete.lock, ignore deleted files
        git diff --diff-filter=ACMRTUXB --name-only ${BRANCH_MAIN}...${BRANCH_CURRENT} | grep -i "^environments" | grep -i "\/delete.lock$" > ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        echo "[+] FYI, list directories contain delete.lock: "
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        sed -i -e 's/delete.lock/helm.yaml/g' ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock >> ${TMPFILE_LISTFILES_COMPARE}
        rm -f ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock

    elif [[ "${BRANCH_CURRENT}" == "${BRANCH_MAIN}" ]];then
        # If this branch is : main
        # We compare two latest commits changed files
        ls -la

        LATEST_COMMIT_HASH=$(git log --pretty=format:'%H' -n 2 | head -n 1)
        PREVIOUS_COMMIT_HASH=$(git log --pretty=format:'%H' -n 2 | tail -n 1)
        git diff --diff-filter=ACMRTUXB --name-only HEAD~1...HEAD | grep -i "^environments" | grep -i "yaml$" > ${TMPFILE_LISTFILES_COMPARE}

        # Check directory have delete.lock
        git diff --diff-filter=ACMRTUXB --name-only HEAD~1...HEAD | grep -i "^environments" | grep -i "\/delete.lock$" > ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock

        echo "[+] FYI, list directories contain delete.lock: "
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        sed -i -e 's/delete.lock/helm.yaml/g' ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock >> ${TMPFILE_LISTFILES_COMPARE}
        rm -f ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
    fi
}

function get_list_helm_found(){
    # Get all list defined yaml
    echo ""
    echo "-------------------------------------------------"
    echo "|   INFRASTRUCTURE KUBERNETES HELM MANAGEMENT   |"
    echo "-------------------------------------------------"
    echo "[*] List file helm.yaml is found :"

    compare_main_and_non_main_branch
    cat ${TMPFILE_LISTFILES_COMPARE}
    echo "*************************"
    if [[ "$(cat ${TMPFILE_LISTFILES_COMPARE} | grep -v "^$" | wc -l | tr -d ' ')" -gt 0 ]];then
        if [[ "${BRANCH_CURRENT}" == "${BRANCH_MAIN}" ]];then
            echo "[+] We find out some changed files between commits branch [main] : ${PREVIOUS_COMMIT_HASH}...${LATEST_COMMIT_HASH}"
        elif [[ "${BRANCH_CURRENT}" != "${BRANCH_MAIN}" ]];then
            echo "[+] We find out some changed files between branches : ${BRANCH_MAIN}...${BRANCH_CURRENT}"
        fi
        cat ${TMPFILE_LISTFILES_COMPARE} | sort | uniq > ${TMPFILE_LIST_HL}

    else
        if [[ "${BRANCH_CURRENT}" == "${BRANCH_MAIN}" ]];then
            echo "[+] We do not find out any changed files between commits branch [main] : ${PREVIOUS_COMMIT_HASH}...${LATEST_COMMIT_HASH}"
        elif [[ "${BRANCH_CURRENT}" != "${BRANCH_MAIN}" ]];then
            echo "[+] We do not find out any changed files between branches : ${BRANCH_MAIN}...${BRANCH_CURRENT}"
        fi

        if [[ "${SCAN_ALL_FILES}" == "true" ]];then
            echo "[+] We found setting: SCAN_ALL_FILES == true"
            echo "[+] So we decide to scan all files yaml"
            find environments -type f -iname "helm.yaml" -o -iname "helm.yml" > ${TMPFILE_LIST_HL}
        else
            echo "[+] We found setting: SCAN_ALL_FILES != true"
            echo "[+] We stop scan all files.yaml"
        fi

    fi

    cat ${TMPFILE_LIST_HL}
}


function get_unique_list_providers(){
    # Get unique list providers
    # environments/stg/aws/stg-eks-main/skeleton/whatsup/helm.yaml
    echo ""
    echo "[*] List unique environmental Providers is found :"
    cat ${TMPFILE_LIST_HL} | awk -F'/' '{print $1 "/" $2 "/" $3 "/" $4}' | sort | uniq | tee ${TMPFILE_LIST_PROVIDERS}
}

function build_k8s_templates_helm(){
    # Process each cloud provider service
    while read line
    do
        # Get information
        SERVICE_METADATA_CONFIG="${line}/metadata.conf"
        SERVICE_TYPE=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "service_type" | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_PROVIDER=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "service_provider" | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_IDENTIFIER=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "service_identifier" | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_ENVIRONMENT=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "environment" | awk -F':' '{print $2}' | tr -d ' ')

        echo ""
        echo "**"
        echo "** $SERVICE_IDENTIFIER **"
        echo "**"
        echo "Processing on this Kubernetes cluster :"
        echo "+ SERVICE_TYPE: $SERVICE_TYPE"
        echo "+ SERVICE_PROVIDER: $SERVICE_PROVIDER"
        echo "+ SERVICE_IDENTIFIDER: $SERVICE_IDENTIFIER"
        echo "+ SERVICE_ENVIRONMENT: ${SERVICE_ENVIRONMENT}"
        echo " "

        # # We need a way to authenticate Kubernetes API
        kubernetes_auth_login $SERVICE_PROVIDER $SERVICE_TYPE $SERVICE_IDENTIFIER $SERVICE_CONTEXT $SERVICE_ENVIRONMENT

        # Get list directory contains file helm.yaml
        cat /dev/null > ${TMPFILE_LIST_HL_DIRS}
        for file in `cat ${TMPFILE_LIST_HL} | grep -i "${line}"`
        do
            dirname $file >> ${TMPFILE_LIST_HL_DIRS}
        done

        cat ${TMPFILE_LIST_HL_DIRS} | grep -v "^$" | sort | uniq > ${TMPFILE_LIST_HL_DIRS}.tmp
        cat ${TMPFILE_LIST_HL_DIRS}.tmp > ${TMPFILE_LIST_HL_DIRS}
        
        if [[ -f ${TMPFILE_LIST_HL_DIRS}.tmp ]];then
            rm -f ${TMPFILE_LIST_HL_DIRS}.tmp
        fi

        ####
        # Get list helm release exists in specific Kubernetes Cluster
        LIST_HELM_RELEASE_K8S=$(mktemp /tmp/tempfile-list-helmreleases-$SERVICE_IDENTIFIER-XXXXXXXX)
        if [[ ! -f ${LIST_HELM_RELEASE_K8S} ]];then
            touch ${LIST_HELM_RELEASE_K8S}
        fi

        echo "[*] List all Helm Release in All Namespaces in Kubernetes Cluster: $SERVICE_IDENTIFIER"
        helm list --all --all-namespaces ${HELM_LIST_MAX_LIMIT} > ${LIST_HELM_RELEASE_K8S}
        cat ${LIST_HELM_RELEASE_K8S}
        echo ""
        ####

        # Process kubectl apply/replace from each directory
        while read directory
        do
            # Read metadata from that helm
            #namespace: cert-manager
            #releaseName: cert-manager
            #environment: staging

            HELM_RELEASE_METADATA_CONFIG="${directory}/helm.yaml"
            HELM_RELEASE_VALUES="${directory}/values.yaml"
            HELM_RELEASE_NAMESPACE=$(cat ${HELM_RELEASE_METADATA_CONFIG} | grep -i "^namespace" | awk -F':' '{print $2}' | tr -d ' ')
            HELM_RELEASE_NAME=$(cat ${HELM_RELEASE_METADATA_CONFIG} | grep -i "releaseName" | awk -F':' '{print $2}' | tr -d ' ')
            HELM_RELEASE_CHART_NAME=$(cat ${HELM_RELEASE_METADATA_CONFIG} | grep -i "chartName" | awk -F':' '{print $2}' | tr -d ' ')
            HELM_RELEASE_CHART_VERSION=$(cat ${HELM_RELEASE_METADATA_CONFIG} | grep -i "chartVersion" | awk -F':' '{print $2}' | tr -d ' ')
            HELM_RELEASE_DELETE_LOCK="${directory}/delete.lock"
            HELM_ENVIRONMENT_META=$(cat ${HELM_RELEASE_METADATA_CONFIG} | grep -i "environment" | awk -F':' '{print $2}' | tr -d ' ')

            # General process
            if [[ -f ${HELM_RELEASE_DELETE_LOCK} ]];then
                HELM_RELEASE_DELETE_MODE="true"
            else
                HELM_RELEASE_DELETE_MODE="false"
            fi

            # Opt argument
            if [[ -f ${HELM_RELEASE_VALUES} ]];then
                OPT_HELM_VALUE="--values ${HELM_RELEASE_VALUES}"
            else
                OPT_HELM_VALUE=""
            fi

            if [[ ${HELM_RELEASE_CHART_VERSION} != "" ]];then
                OPT_HELM_CHART_VERSION="--version ${HELM_RELEASE_CHART_VERSION}"
                HELM_RELEASE_CHART_VERSION_INFO="${HELM_RELEASE_CHART_VERSION}"
            else
                OPT_HELM_CHART_VERSION=""
                HELM_RELEASE_CHART_VERSION_INFO="latest"
            fi


            # Info
            echo "|______________________________________________________________________________________________|"
            echo ""
            echo "|______________________________________________________________________________________________|"
            echo "<<  ${HELM_RELEASE_NAME}  >>"
            echo ""
            echo "[-] Found Helm Release config: ${directory}/helm.yaml"
            echo "[-] Helm Release Name: ${HELM_RELEASE_NAME}"
            echo "[-] Helm Release Namespace: ${HELM_RELEASE_NAMESPACE}"
            echo "[-] Helm Chart Name: ${HELM_RELEASE_CHART_NAME}"
            echo "[-] Helm Chart Version: ${HELM_RELEASE_CHART_VERSION_INFO}"
            echo "[-] Helm Release Value: ${HELM_RELEASE_VALUES}"
            echo "[-] Helm Delete Mode: ${HELM_RELEASE_DELETE_MODE}"
            echo "[-] Helm Environment Meta: ${HELM_ENVIRONMENT_META}"
            echo ""

            ####
            # If this Helm Release does not exists in Kubernetes Cluster
            # We will install it
            if [[ ! "$(grep -i "${HELM_RELEASE_NAMESPACE}" ${LIST_HELM_RELEASE_K8S} | awk '{print $1}' | grep -i "^${HELM_RELEASE_NAME}$")" ]];then
                echo "[+] CHECKING: not found Helm Release [${HELM_RELEASE_NAME}] namespace ["${HELM_RELEASE_NAMESPACE}"] in Kubernetes Cluster [$SERVICE_IDENTIFIER]"

                # If not found Helm Release, and this directory app in DeleteMode
                # Means: this Helm Release is deleted
                if [[ "${HELM_RELEASE_DELETE_MODE}" == "true" ]];then
                    echo "[-] ActionType: ${ACTION}"
                    echo "[>] Result [${ACTION}]: this Helm Release is deleted and still in Delete Mode, no handle this Helm Release anymore."
                    continue
                fi

                # If action "APPLY" on branch MASTER, will make it install
                if [[ $ACTION == "apply" ]];then
                    echo "[-] ActionType: ${ACTION}"

                    # Install if not in delete mode
                    echo "[>] Result [${ACTION}]: install this Helm Release [${HELM_RELEASE_NAME}] on Namespace [$HELM_RELEASE_NAMESPACE]"

                    # Debug option
                    if [[ "${DEBUG}" == "debug" ]];then
                        echo "[=] Debug: enabled"
                        echo "helm install --wait ${OPT_HELM_VALUE} ${OPT_HELM_CHART_VERSION} \
                            --create-namespace --namespace ${HELM_RELEASE_NAMESPACE} \
                            ${HELM_RELEASE_NAME} \
                            ${HELM_PRIVATE_REPO_NAME}/${HELM_RELEASE_CHART_NAME}" | tr -s ' ' ' - '
                        
                    fi

                    # Delete secret match this helm-release if exists
                    if [[ $(kubectl get secrets -n ${HELM_RELEASE_NAMESPACE} | awk '{print $1}' | grep "^${HELM_RELEASE_NAME}$") ]];then
                        echo "[+] Found exising secret mapping HelmRelease: ${HELM_RELEASE_NAME}"
                        echo "[-] Action: delete this existing secret => namespace: ${HELM_RELEASE_NAMESPACE} - secret: ${HELM_RELEASE_NAME}"
                        kubectl delete secrets -n ${HELM_RELEASE_NAMESPACE} ${HELM_RELEASE_NAME}
                    fi

                    helm install ${OPT_HELM_VALUE} ${OPT_HELM_CHART_VERSION} \
                        --create-namespace --namespace ${HELM_RELEASE_NAMESPACE} \
                        ${HELM_RELEASE_NAME} \
                        ${HELM_PRIVATE_REPO_NAME}/${HELM_RELEASE_CHART_NAME}

                    echo $?

                else
                    echo "[-] ActionType: ${ACTION}"
                    echo "[>] Result [${ACTION}]: do not install/delete this Helm Release based on ActionType [$ACTION]. We will install/delete this Helm Release when ActionType is APPLY"
                fi

                # Continue to proceed next Chart
                continue
            else
                echo "[+] CHECKING: found Helm Release [${HELM_RELEASE_NAME}] namespace ["${HELM_RELEASE_NAMESPACE}"] in Kubernetes Cluster [$SERVICE_IDENTIFIER]"
            fi
            ####

            ####
            # If this Helm Release exists in Helm Release list
            # 1. if this Helm Release Config in Delete Mode
            # we will delete this Helm Release and continue
            if [[ "${HELM_RELEASE_DELETE_MODE}" == "true" ]];then
                if [[ $ACTION == "apply" ]];then
                    echo "[-] ActionType: ${ACTION}"
                    echo "[>] Result [${ACTION}]: delete this Helm Release"
                    helm delete --namespace ${HELM_RELEASE_NAMESPACE} ${HELM_RELEASE_NAME}
                else
                    echo "[-] ActionType: ${ACTION}"
                    echo "[>] Result [${ACTION}]: do not delete this Helm Release based on ActionType [$ACTION]"
                fi

                continue
            fi

            # 2. if this Helm Release Config not in Delete Mode
            # We will check helm diff to know what changed, then proceed
            TMPFILE_HELM_DIFF_RELEASE=$(mktemp /tmp/tempfile-helmrelease-diff-$HELM_RELEASE_NAME-XXXXXXXX)
            echo "[+] Helm diff render to new changes:"
            helm diff upgrade --no-color ${OPT_HELM_VALUE} ${OPT_HELM_CHART_VERSION} \
                    --namespace ${HELM_RELEASE_NAMESPACE} \
                    ${HELM_RELEASE_NAME} \
                    ${HELM_PRIVATE_REPO_NAME}/${HELM_RELEASE_CHART_NAME} | tee -a ${TMPFILE_HELM_DIFF_RELEASE}

            # If we found changed in helm diff, we will helm upgrade to update helmRelease
            echo ""
            if [[ $(cat ${TMPFILE_HELM_DIFF_RELEASE} | wc -l) -gt 0 ]];then
                    echo "[-] Found some changes in this Helm Release [${HELM_RELEASE_NAME}]"

                    # Situation 1: we want to ignore upgrade change in deployment
                    # has change at: annotation.timestamp & image:tag
                    # Check only on general-application app
                    # # Source: general-application/
                    COUNT_GENERAL_APPLICATION_SOURCE=$(cat ${TMPFILE_HELM_DIFF_RELEASE} | grep -i "# Source: general-application/" | wc -l  | tr -d ' ')
                    COUNT_GENERAL_APPLICATION_DEPLOYMENT=$(cat ${TMPFILE_HELM_DIFF_RELEASE} | grep -i "general-application/templates/deployment.yaml" | wc -l  | tr -d ' ')
                    FLAG_FOUND_ONLY_DEPLOYMENT_WITH_NO_CHANGE="false"
                    if [[ ${COUNT_GENERAL_APPLICATION_SOURCE} -eq ${COUNT_GENERAL_APPLICATION_DEPLOYMENT} ]];then
                        # If found change in other except annotation.timestamp & image:tag, will continue to upgrade
                        COUNT_CHANGE_DEPLOYMENT=$(cat ${TMPFILE_HELM_DIFF_RELEASE} | grep -Ev "timestamp:|image:" | grep -Ei "^\+|^-" | wc -l | tr -d ' ')
                        if [[ ${COUNT_CHANGE_DEPLOYMENT} -eq 0 ]];then
                            echo "[-] Detect something changes in General-Application App Deployment"
                            echo "[-] But not found any changes (except: annotation.timestamp & image.tag) in this Helm Release [${HELM_RELEASE_NAME}]"
                            echo "[>] Result [${ACTION}]: no proceed upgrade this Helm Release"
                            FLAG_FOUND_ONLY_DEPLOYMENT_WITH_NO_CHANGE="true"
                        fi
                    fi

                    # If action "APPLY" on branch MASTER, will make it deploy
                    if [[ ${FLAG_FOUND_ONLY_DEPLOYMENT_WITH_NO_CHANGE} == "false" ]];then
                        if [[ $ACTION == "apply" ]];then
                            echo "[-] ActionType: ${ACTION}"
                            echo "[>] Result [${ACTION}]: proceed upgrade this Helm Release"

                            # Debug option
                            if [[ "${DEBUG}" == "debug" ]];then
                                echo "[=] Debug: enabled"
                                echo "helm upgrade --wait ${OPT_HELM_VALUE} ${OPT_HELM_CHART_VERSION} \
                                    --create-namespace --namespace ${HELM_RELEASE_NAMESPACE} \
                                    ${HELM_RELEASE_NAME} \
                                    ${HELM_PRIVATE_REPO_NAME}/${HELM_RELEASE_CHART_NAME}" | tr -s ' ' ' - '
                                
                            fi

                            helm upgrade --wait ${OPT_HELM_VALUE} ${OPT_HELM_CHART_VERSION} \
                                --create-namespace --namespace ${HELM_RELEASE_NAMESPACE} \
                                ${HELM_RELEASE_NAME} \
                                ${HELM_PRIVATE_REPO_NAME}/${HELM_RELEASE_CHART_NAME}

                            echo $?

                        else
                            echo "[-] ActionType: ${ACTION}"
                            echo "[>] Result [${ACTION}]: do not upgrade this Helm Release based on ActionType [$ACTION]"
                        fi
                    fi
            else
                echo "[-] Not found any changes in this Helm Release [${HELM_RELEASE_NAME}]"
                echo "[>] Result [${ACTION}]: no proceed upgrade this Helm Release"

            fi

            function reConnect() {
                RAMDOM_NUM=$((30 + $RANDOM % 90))
                echo "Server can't connect, we will waiting ${RAMDOM_NUM}s and auto try again."
                sleep ${RAMDOM_NUM}
                # We will remove old config k8s
                [ -d "$HOME/.kube" ] && rm -rf "$HOME/.kube" || echo "Folder is not exists !"
                # Recreate config k8s and apply env
                kubernetes_auth_login $SERVICE_PROVIDER $SERVICE_TYPE $SERVICE_IDENTIFIER $SERVICE_CONTEXT $SERVICE_ENVIRONMENT 
            }

            until $(kubectl cluster-info &>/dev/null)
            do
                reConnect
            done

            echo ""
            echo "[*] Done"

            # Cleanup temporary files
            if [[ -f ${TMPFILE_HELM_DIFF_RELEASE} ]];then
                rm -f ${TMPFILE_HELM_DIFF_RELEASE}
            fi
            
        done < ${TMPFILE_LIST_HL_DIRS}

        # Cleanup when done process each kubernetes provider
        if [[ -f ${LIST_HELM_RELEASE_K8S} ]];then
            rm -f ${LIST_HELM_RELEASE_K8S}
        fi

    done < ${TMPFILE_LIST_PROVIDERS}

}

################
#   Main flow  #
################

###### START
function main(){
    # Action based on ${ACTION} arg
    case ${ACTION} in
    "-v" | "--version")
        about
        ;;
    "-h" | "--help")
        help
        ;;
    *)
        # Init tempfile, call function init()
        init

        # Checking supported tool & plugin on local machine
        pre_check_dependencies "helm"

        # Pre-checking
        pre_checking
        
        # Add Company Private Helm Repository
        connect_helm_repo

        get_list_helm_found

        get_unique_list_providers

        build_k8s_templates_helm
        ;;
    esac

    # Clean trash of service
    cleanup
}

main "${@}"

exit 0
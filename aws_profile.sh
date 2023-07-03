#!/bin/bash
# This scripts is used to login multiple aws profile credentials

echo ""
echo "-------------------------------------"
echo "|   AWS PROFILE CREDENTIALS SETUP   |"
echo "-------------------------------------"

echo "[*] AWS Credentials Setup"

TMPFILE=$(mktemp /tmp/tempfile-XXXXXXXX)
TMPDIR_AWS_LOGIN=$(mktemp -d /tmp/aws-credentials-login-XXXXXX)

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
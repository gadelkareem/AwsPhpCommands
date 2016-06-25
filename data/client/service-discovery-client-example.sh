#!/usr/bin/env bash


#######################
#     Example Client             #
#######################


set -e

pidfile="/tmp/service-discovery-client"

# lock the script
exec 200>$pidfile
flock -n 200 || ( echo "service discovery client is already running. Aborting . . " && exit 1 )
pid=$$
echo $pid 1>&200


populate_env_vars()
{
    #Populate /etc/environment if it was modified
    for line in $( cat /etc/environment ) ; do
        if [ "$line" != "" ]; then
            export $line || true
        fi
    done
}

ENV_TYPE=testing

if [ "$APP_ENV" = "prod" ]
then
    ENV_TYPE=prod
fi

DIR=/root/services-info
FILE=services-info-${ENV_TYPE}.json

#Use --skip-existing parameter to skip overwriting file
FORCE="--force"
if [ "$1" == "--skip-existing" ]; then
    FORCE="--skip-existing"
fi

mkdir -p ${DIR}

#http://s3tools.org/download
s3cmd get ${FORCE} s3://services.store/${FILE}.des3 ${DIR}/${FILE}.des3

#decrypt file
/root/endec_all  -o /tmp -d ${DIR}/${FILE}.des3

#The end file will be called services-info.json regardless the ENV
mv /tmp/${FILE} ${DIR}/services-info.json

populate_env_vars

#load custom client
php custom-client.php


if [[ "$1" != "--skip-existing" ]]; then
    populate_env_vars
    sudo service nginx reload
fi


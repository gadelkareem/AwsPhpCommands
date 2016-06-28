# [AWS PHP Commands](https://github.com/gadelkareem/AwsPhpCommands)
A group of AWS Cli commands for devOps

## [Service Discovery Command](http://gadelkareem.com/2016/06/28/aws-php-service-discovery/)

[Service Discovery](https://github.com/gadelkareem/AwsPhpCommands/blob/master/src/AwsPhpCommands/ServiceDiscovery/ServiceDiscoveryCommand.php "Service Discovery") is a simple PHP command to collect and store AWS information such as [EC2s](https://aws.amazon.com/ec2/) and [RDSs](https://aws.amazon.com/rds/) in the current [region](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html) and save them with their credentials into an encrypted JSON file on [S3](https://aws.amazon.com/s3/). The script later notifies each service via SSH and executes the service discovery client on each instance. Each client downloads the JSON file and uses it to configure different applications. It can easily be automated through [Rundeck](http://rundeck.org/) or [Jenkins](https://jenkins.io/) to be executed after each deploy. Service Discovery is part of [AWS PHP Commands](https://github.com/gadelkareem/AwsPhpCommands). Usage:

```
> php console.php aws:services:discover -h
Usage:
  aws:services:discover [options]

Options:
  -f, --forceNotify[=FORCENOTIFY]          Force Notify [default: false]
  -e, --notifyOnly[=NOTIFYONLY]            Notify only one of dev,prod [default: false]
  -c, --continueOnError[=CONTINUEONERROR]  Continue to next EC2 on client failure [default: false]
  -h, --help                               Display this help message
  -q, --quiet                              Do not output any message
  -V, --version                            Display this application version
      --ansi                               Force ANSI output
      --no-ansi                            Disable ANSI output
  -n, --no-interaction                     Do not ask any interactive question
  -v|vv|vvv, --verbose                     Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug

Help:
 Discovers services information and credentials.
```

##### Configuration

*   Required Environment Variables

  *   AWS Keys: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
  *   Encryption passwords : `DEV_ENC_PASS` for dev environment and `PROD_ENC_PASS` for production environment (currently set as **"prod_test"**).

*   [endec.sh](https://github.com/gadelkareem/AwsPhpCommands/blob/master/data/endec/endec.sh):

  *   `AwsPhpCommands/data/endec/endec.sh` is bash script that uses [OpenSSL](https://en.wikipedia.org/wiki/OpenSSL) for encrypting/decrypting files.
  *   The password used for encryption `ENC_PASS` should be added to your environment variables depending on the environment to use with [Service Discovery Client](https://github.com/gadelkareem/AwsPhpCommands/blob/master/data/client/service-discovery-client-example.sh).

*   [Services Credentials](https://github.com/gadelkareem/AwsPhpCommands/blob/master/keys/service-discovery/credentials.json.example):

  *   All services credentials are saved and encrypted using endec.sh script in `keys/service-discovery/credentials.json.enc` file.
  *   To decrypt the file use

      `export $PROD_ENC_PASS=prod_test; ./data/endec/endec.sh -o keys/service-discovery/ -d keys/service-discovery/credentials.json.enc`

  *   To encrypt back use

      `export $PROD_ENC_PASS=prod_test; ./data/endec/endec.sh -o keys/service-discovery/ -e keys/service-discovery/credentials.json`

*   `\AwsPhpCommands\ServiceDiscovery\ServiceDiscoveryCommand::S3_BUCKET` is the S3 bucket name.
*   `\AwsPhpCommands\ServiceDiscovery\ServiceDiscoveryCommand::$WHITE_LIST_CIDRS` contains a whitelist of IP ranges.
*   [Services Discovery Client](https://github.com/gadelkareem/AwsPhpCommands/blob/master/data/client/service-discovery-client-example.sh):

  *   The service logs into each instance via SSH and executes `/root/service-discovery-client.sh` script to download the `services-info.json.enc` file from S3 and decrypt it.
  *   All private keys should be added in `/root/.ssh/` directory on the same server running the Service Discovery.
  *   `\AwsPhpCommands\ServiceDiscovery\ServiceDiscoveryCommand::$KEYNAME_LOGINS` contains the EC2 key name as key and login username as value.

##### Example JSON

```
{
  "servicesInfo": {
    "ec2s": {
      "instance-name-prod": [
        {
          "id": "i-62882e2f",
          "name": "instance-name-prod",
          "keyName": "key-example",
          "publicIp": "74.125.224.72",
          "privateIp": "172.31.5.119",
          "securityGroup": "group_prod",
          "vpcId": "vpc-cd4x23ef",
          "tags": {
            "Name": "instance-name-prod"
          },
          "credentials": {
            "someService": {
              "username": "user_prod",
              "password": "prod_pass"
            }
          }
        }
      ]
    },
    "rdss": {
      "rds-name-prod": {
        "id": "rds-name-prod",
        "name": "rds-name-prod",
        "endpoint": "rds-name-prod.dfgadfg4df.us-west-1.rds.amazonaws.com",
        "securityGroup": "sg-2b2c86fd",
        "port": 3306,
        "credentials": {
          "dbOne": {
            "username": "user_prod",
            "dbName": "db_prod",
            "password": "prod_pass"
          },
          "dbTwo": {
            "username": "user_prod",
            "dbName": "db_prod",
            "password": "prod_pass"
          }
        }
      }
    },
    "servicesCredentials": {
      "instance-name-prod": {
        "someService": {
          "username": "user_prod",
          "password": "prod_pass"
        }
      },
      "instance-name-dev": {
        "someService": {
          "username": "user_dev",
          "password": "dev_pass"
        }
      },
      "rds-name-prod": {
        "dbOne": {
          "username": "user_prod",
          "dbName": "db_prod",
          "password": "prod_pass"
        },
        "dbTwo": {
          "username": "user_prod",
          "dbName": "db_prod",
          "password": "prod_pass"
        }
      },
      "rds-name-dev": {
        "dbOne": {
          "username": "user_dev",
          "dbName": "db_dev",
          "password": "dev_pass"
        },
        "dbTwo": {
          "username": "user_dev",
          "dbName": "db_dev",
          "password": "dev_pass"
        }
      }
    },
    "publicIps": [
      "74.125.224.72"
    ],
    "privateIps": [
      "172.31.5.119",
      "172.31.1.10"
    ],
    "whiteListCidrs": [
      "64.18.0.0\/20",
      "172.31.0.0\/16",
      "74.125.224.72\/32",
    ]
  }
}
```

###For support please visit [AWS PHP Service Discovery](http://gadelkareem.com/2016/06/28/aws-php-service-discovery/)
___





## [AWS PHP Modify Security Groups Command](http://gadelkareem.com/2016/06/26/aws-php-modify-security-groups-command/)

[Modify Security Groups Command](https://github.com/gadelkareem/AwsPhpCommands/blob/master/src/AwsPhpCommands/ModifySecurityGroups/ModifySecurityGroupsCommand.php "Modify Security Groups Command") is an easy to use command that you can add to your DevOps to allow adding/Removing IPs or CIDRs to [AWS security groups](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html) for all protocol and ports. The command is part of [AWS PHP Commands](https://github.com/gadelkareem/AwsPhpCommands). 

#### Usage:

```
> php console.php aws:security-groups:modify -h
Usage:
  aws:security-groups:modify [options]

Options:
  -c, --cidr=CIDR            CIDR ex: 64.18.0.0/20 [default: false]
  -o, --operation=OPERATION  Operation to perform, one of add or remove [default: "add"]
  -e, --env[=ENV]            Which security groups this should run on. One of prod, dev [default: "dev"]
  -h, --help                 Display this help message
  -q, --quiet                Do not output any message
  -V, --version              Display this application version
      --ansi                 Force ANSI output
      --no-ansi              Disable ANSI output
  -n, --no-interaction       Do not ask any interactive question
  -v|vv|vvv, --verbose       Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug

Help:
 Adds/removes CIDRs to security groups.
```

###For support please visit [AWS PHP Modify Security Groups Command Page](http://gadelkareem.com/2016/06/26/aws-php-modify-security-groups-command/)

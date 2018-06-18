<?php

/*
 * This file is part of the AwsPhpCommands package.
 *
 * (c) Gadelkareem <gadelkareem.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AwsPhpCommands\ServiceDiscovery;

use Aws\Ec2\Ec2Client;
use Aws\Rds\RdsClient;
use Aws\S3\S3Client;
use phpseclib\Crypt\RSA;
use phpseclib\Net\SSH2;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

/**
 * Class ServiceDiscoveryCommand.
 */
class ServiceDiscoveryCommand extends Command
{
    /**
     *  List of private key names with their corresponding login username
     *  All keys should be saved in /root/.ssh/{keyName}.
     *
     * @var array
     */
    public static $KEYNAME_LOGINS = [
        'key-example' => 'ubuntu',
    ];

    /**
     * S3 bucket name.
     *
     * @var string
     */
    const S3_BUCKET = 'services.store';

    /**
     *  List of internal or trusted IPs.
     *
     * @var array
     */
    public static $WHITE_LIST_CIDRS = [
        '64.18.0.0/20', //Public IPs
        '172.31.0.0/16', //AWS VPC
    ];

    /**
     * Path to service discovery directory where service-info.json
     * will be generated.
     *
     * @var string
     */
    private $dataDirectory;

    /**
     *  Path to the script to encrypt the services-info.json: endec.sh.
     *
     * @var string
     */
    private $endecPath;

    /**
     * @var Ec2Client
     */
    private $awsClient;

    /**
     * @var RdsClient
     */
    private $rdsClient;

    /**
     * @var S3Client
     */
    private $s3Client;

    /**
     * @var InputInterface
     */
    private $input;

    /**
     * @var string
     */
    private $notifyOnly;

    /**
     * @var OutputInterface
     */
    private $output;

    /**
     * @var array
     */
    private $credentials = [];

    /**
     *  Main service info store.
     *
     * @var array
     */
    private $servicesInfo = [];

    /**
     * Cache for different services environments info.
     *
     * @var array
     */
    private $servicesInfoCache = [];

    /**
     * @var array
     */
    private $envTypes = ['dev', 'prod'];

    /**
     *  Environment specific password for encrypting/decrypting files.
     *
     * @var array
     */
    private $encryptionPasswords = [];

    protected function configure()
    {
        $this->setName('aws:services:discover')
            ->setDescription('Discovers services information and credentials.')
            ->addOption(
                'forceNotify',
                'f',
                InputOption::VALUE_OPTIONAL,
                'Force Notify',
                false
            )->addOption(
                'notifyOnly',
                'e',
                InputOption::VALUE_OPTIONAL,
                'Notify only one of '.implode(',', $this->envTypes),
                false
            )->addOption(
                'continueOnError',
                'c',
                InputOption::VALUE_OPTIONAL,
                'Continue to next EC2 on client failure',
                false
            );
    }

    /**
     * @param InputInterface  $input
     * @param OutputInterface $output
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->setup($input, $output);
        $this->setCredentials();
        $ec2Count = $this->getEc2s();
        $this->output->writeln("- Found {$ec2Count} EC2s running.");
        $rdsCount = $this->getRdss();
        $this->output->writeln("- Found {$rdsCount} RDSs running.");

        $this->servicesInfo['servicesCredentials'] = $this->getCredentials();
        $this->servicesInfoCache['prod']['servicesCredentials'] = $this->getCredentials('prod');
        $this->servicesInfoCache['dev']['servicesCredentials'] = $this->getCredentials('dev');

        $this->servicesInfo['whiteListCidrs'] = $this->getWhiteListCidrs();
        $this->servicesInfoCache['prod']['whiteListCidrs'] = $this->servicesInfo['whiteListCidrs'];
        $this->servicesInfoCache['dev']['whiteListCidrs'] = $this->servicesInfo['whiteListCidrs'];

        //Allow a combined collection of all services info for all environments
        $this->envTypes[] = 'all';

        foreach ($this->envTypes as $envType) {
            $this->output->writeln(PHP_EOL."Checking {$envType} services");
            $servicesModified = $this->encryptServiceInfoFile($envType);
            if ($servicesModified || $input->getOption('forceNotify')) {
                $this->uploadToS3($envType);
                if ($envType != 'all' && (!$this->notifyOnly || $envType == $this->notifyOnly)) {
                    $this->notifyServices($envType);
                }
            }
        }
    }

    /**
     * @param InputInterface  $input
     * @param OutputInterface $output
     */
    private function setup(InputInterface $input, OutputInterface $output)
    {
        $this->input = $input;
        $this->output = $output;

        $this->dataDirectory = DATA_DIR.'/service-discovery';
        $this->endecPath = DATA_DIR.'/endec/endec.sh';

        if (!getenv('AWS_ACCESS_KEY_ID') || !getenv('AWS_SECRET_ACCESS_KEY')) {
            throw new \InvalidArgumentException('No AWS keys found! Please add your AWS keys to your environment variables.');
        }

        if (!getenv('DEV_ENC_PASS') || !getenv('PROD_ENC_PASS')) {
            throw new \InvalidArgumentException("Encryption passwords were not found! Please add 'DEV_ENC_PASS' and 'PROD_ENC_PASS' to your environment variables.");
        }
        $this->encryptionPasswords = [
            'dev'  => getenv('DEV_ENC_PASS'),
            'prod' => getenv('PROD_ENC_PASS'),
            'all'  => getenv('PROD_ENC_PASS'),
        ];

        if ($this->input->getOption('notifyOnly') &&
            !in_array($this->input->getOption('notifyOnly'), $this->envTypes)
        ) {
            throw new \InvalidArgumentException('Invalid notifyOnly. Please use one of '.
                implode(',', $this->envTypes)
            );
        }
        $this->notifyOnly = $this->input->getOption('notifyOnly');

        $config = [
            'version'     => '2015-10-01',
            'region'      => 'us-west-1',
            'credentials' => [
                'key'    => getenv('AWS_ACCESS_KEY_ID'),
                'secret' => getenv('AWS_SECRET_ACCESS_KEY'),
            ],
        ];

        $this->awsClient = new Ec2Client($config);
        $config['version'] = '2014-10-31';
        $this->rdsClient = new RdsClient($config);
        $config['version'] = '2006-03-01';
        $this->s3Client = new S3Client($config);
    }

    /**
     * Read credentials from encrypted credentials.json.enc file.
     *
     * @throws \RuntimeException if credentials.json.enc file does not exist
     */
    private function setCredentials()
    {
        $keysDir = KEYS_DIR.'/service-discovery';
        $credentialsFile = "{$keysDir}/credentials.json";
        clearstatcache();
        if (!file_exists($credentialsFile.'.enc')) {
            throw new \RuntimeException(
                "Please encrypt file {$credentialsFile} to continue: ".PHP_EOL.
                "{$this->endecPath} -o {$keysDir}/ -e {$credentialsFile}".PHP_EOL.PHP_EOL
            );
        }
        $this->endec($credentialsFile.'.enc', $keysDir, 'prod', false);

        $this->credentials = json_decode(file_get_contents($credentialsFile), true);
        if (!is_array($this->credentials)) {
            throw new \RuntimeException("Please make sure file {$credentialsFile} exists and is valid json.");
        }
        clearstatcache();
        unlink($credentialsFile);
    }

    /**
     * @param null|string $envType
     *
     * @return array
     */
    public function getCredentials($envType = null)
    {
        $credentials = $this->credentials['servicesCredentials'];
        if (!$envType) {
            return $credentials;
        }
        foreach ($credentials as $instanceName => $info) {
            $isProd = $this->isProd($instanceName);
            if (($isProd && $envType == 'dev') ||
                (!$isProd && $envType == 'prod')
            ) {
                unset($credentials[$instanceName]);
            }
        }

        return $credentials;
    }

    /**
     * Gathers public IPs and save it into servicesInfo array.
     *
     * @return array
     */
    public function getWhiteListCidrs()
    {
        $cidrs = static::$WHITE_LIST_CIDRS;
        $ips = $this->servicesInfo['publicIps'];
        foreach ($ips as $ip) {
            $cidrs[] = $ip.'/32';
        }

        return $cidrs;
    }

    /**
     * Gathers EC2s info and save it into servicesInfo array.
     *
     * @return int
     */
    private function getEc2s()
    {
        $ec2Count = 0;

        $this->servicesInfo['ec2s'] = [];
        $this->servicesInfo['publicIps'] = [];
        $this->servicesInfo['privateIps'] = [];
        foreach ($this->envTypes as $env) {
            $this->servicesInfoCache[$env]['ec2s'] = [];
            $this->servicesInfoCache[$env]['publicIps'] = [];
            $this->servicesInfoCache[$env]['privateIps'] = [];
        }

        $result = $this->awsClient->describeInstances();
        $reservations = $result['Reservations'];

        foreach ($reservations as $reservation) {
            $instances = $reservation['Instances'];

            foreach ($instances as $instance) {
                if ($instance['State']['Name'] != 'running') {
                    continue;
                }
                $tags = [];
                foreach ($instance['Tags'] as $tag) {
                    $tags[$tag['Key']] = $tag['Value'];
                }
                $instanceName = isset($tags['Name']) ? $tags['Name'] : $instance['InstanceId'];

                $credentials = $this->findCredentials($instanceName);

                /**
                 * Distinguishes between different instances with the same instanceName.
                 *
                 * @var int
                 */
                $instanceCount = isset($this->servicesInfo['ec2s'][$instanceName]) ? count($this->servicesInfo['ec2s'][$instanceName]) : 0;

                $this->servicesInfo['ec2s'][$instanceName][$instanceCount] = [
                    'id'              => $instance['InstanceId'],
                    'name'            => $instanceName,
                    'keyName'         => $instance['KeyName'],
                    'publicIp'        => $instance['PublicIpAddress'],
                    'privateIp'       => $instance['PrivateIpAddress'],
                    'securityGroup'   => $instance['SecurityGroups'][0]['GroupName'],
                    'securityGroupId' => $instance['SecurityGroups'][0]['GroupId'],
                    'vpcId'           => $instance['VpcId'],
                    'tags'            => $tags,
                    'credentials'     => $credentials,
                ];
                $this->servicesInfo['publicIps'][] = $instance['PublicIpAddress'];
                $this->servicesInfo['privateIps'][] = $instance['PrivateIpAddress'];

                $envType = $this->isProd($instanceName) ? 'prod' : 'dev';
                $this->servicesInfoCache[$envType]['ec2s'][$instanceName][$instanceCount] = $this->servicesInfo['ec2s'][$instanceName][$instanceCount];
                $this->servicesInfoCache[$envType]['publicIps'][] = $instance['PublicIpAddress'];
                $this->servicesInfoCache[$envType]['privateIps'][] = $instance['PrivateIpAddress'];
                $ec2Count++;
            }
        }

        return $ec2Count;
    }

    /**
     * Gathers RDSs info and save it into servicesInfo array.
     *
     * @return int
     */
    private function getRdss()
    {
        $rdsCount = 0;
        $this->servicesInfo['rdss'] = [];
        foreach ($this->envTypes as $env) {
            $this->servicesInfoCache[$env]['rdss'] = [];
        }
        $result = $this->rdsClient->describeDBInstances();

        foreach ($result['DBInstances'] as $instance) {
            $instanceName = $instance['DBInstanceIdentifier'];

            $credentials = $this->findCredentials($instanceName);

            $this->servicesInfo['rdss'][$instanceName] = [
                'id'            => $instanceName,
                'name'          => $instanceName,
                'endpoint'      => $instance['Endpoint']['Address'],
                'securityGroup' => $instance['VpcSecurityGroups'][0]['VpcSecurityGroupId'],
                'port'          => $instance['Endpoint']['Port'],
                'credentials'   => $credentials,
            ];

            $envType = $this->isProd($instanceName) ? 'prod' : 'dev';
            $this->servicesInfoCache[$envType]['rdss'][$instanceName] = $this->servicesInfo['rdss'][$instanceName];
            $rdsCount++;
        }

        return $rdsCount;
    }

    /**
     * @param $instanceName
     *
     * @return null|array
     */
    private function findCredentials($instanceName)
    {
        $credentials = null;
        if (!$credentials && isset($this->credentials['servicesCredentials'][$instanceName])) {
            $credentials = $this->credentials['servicesCredentials'][$instanceName];
        }

        return $credentials;
    }

    /**
     * Encrypt the service-info.json file and check if there are any changes.
     *
     * @param $envType
     *
     * @return bool true if there are new services found false otherwise
     */
    private function encryptServiceInfoFile($envType)
    {
        $old_md5 = '';
        $jsonContent = $this->toJson($envType);
        $md5 = md5($jsonContent);
        $serviceInfoPath = $this->dataDirectory."/services-info-{$envType}.json";
        clearstatcache();
        if (file_exists($serviceInfoPath.'.enc')) {
            $this->endec($serviceInfoPath.'.enc', $this->dataDirectory, $envType, false);
            clearstatcache();
            if (file_exists($serviceInfoPath)) {
                $old_md5 = md5(file_get_contents($serviceInfoPath));
                unlink($serviceInfoPath);
            }
        }

        if ($old_md5 != $md5) {
            $this->output->writeln('Services info modified.');
            file_put_contents($serviceInfoPath, $jsonContent, LOCK_EX);
            $this->endec($serviceInfoPath, $this->dataDirectory, $envType);
            clearstatcache();
            unlink($serviceInfoPath);

            return true;
        } else {
            $this->output->writeln('No changes to services.');

            return false;
        }
    }

    /**
     * @param string $envType
     */
    private function uploadToS3($envType)
    {
        $bucket = self::S3_BUCKET;

        $this->output->writeln('- Uploading to S3...');
        $this->s3Client->putObject([
            'Bucket'     => $bucket,
            'Key'        => "services-info-{$envType}.json.enc",
            'SourceFile' => $this->dataDirectory."/services-info-{$envType}.json.enc",
        ]);

        $this->s3Client->waitUntil('ObjectExists', [
            'Bucket' => $bucket,
            'Key'    => "services-info-{$envType}.json.enc",
        ]);
    }

    /**
     * @param $envType
     */
    private function notifyServices($envType)
    {
        $ec2s = $this->servicesInfoCache[$envType]['ec2s'];

        foreach ($ec2s as $ec2Count) {
            foreach ($ec2Count as $ec2) {
                $this->executeClient($ec2);
            }
        }
    }

    /**
     * Login to the EC2 and execute the service discovery client.
     *
     * @param array  $ec2
     * @param string $client
     */
    private function executeClient($ec2, $client = '/root/service-discovery-client.sh')
    {
        $ip = $ec2[APP_ENV == 'dev' ? 'publicIp' : 'privateIp'];
        $keyPath = '/root/.ssh/'.$ec2['keyName'];

        if (!file_exists($keyPath) || isset(self::$KEYNAME_LOGINS[$ec2['keyName']])) {
            $this->output->writeln("- Host {$ip} {$ec2['name']} has a different key '{$ec2['keyName']}'. Skipping ...");

            return;
        }

        $ssh = new SSH2($ip);
        $key = new RSA();
        $key->loadKey(file_get_contents($keyPath));

        if (!$ssh->login(self::$KEYNAME_LOGINS[$ec2['keyName']], $key)) {
            throw new \RuntimeException("Could not login to host {$ip}.");
        }
        $ssh->exec("sudo test -f {$client}");

        if ($ssh->getExitStatus() != 0) {
            $this->output->writeln("- Host {$ip} {$ec2['name']} has no client. Skipping ...");
        } else {
            $ssh->exec("sudo {$client}");
            if ($ssh->getExitStatus() != 0) {
                $message = "- Error running client on {$ip}.".PHP_EOL.
                    var_export($ssh->getErrors(), true);
                if ($this->input->getOption('continueOnError')) {
                    $this->output->writeln($message);

                    return;
                }

                throw new \RuntimeException($message);
            } else {
                $this->output->writeln("<info>- Host {$ip} {$ec2['name']} updated successfully.</info>");
            }
        }
    }

    /**
     *  Encrypt/decrypt file using endec.sh script.
     *
     * @param string $filePath
     * @param string $location
     * @param string $envType
     * @param string $type
     *
     * @throws ProcessFailedException
     */
    private function endec($filePath, $location, $envType, $encrypt = true)
    {
        putenv("ENC_PASS={$this->encryptionPasswords[$envType]}");

        $command = "{$this->endecPath} -o {$location}";
        $command .= $encrypt ? ' -e ' : ' -d ';
        $command .= $filePath;

        $process = new Process($command);
        $process->setEnv(['ENC_PASS' => $this->encryptionPasswords[$envType]])
            ->run();

        if (!$process->isSuccessful()) {
            throw new ProcessFailedException($process);
        }
    }

    /**
     * @param $envType
     *
     * @return string
     */
    private function toJson($envType)
    {
        $servicesInfo = $envType != 'all' ?
            $this->servicesInfoCache[$envType] : $this->servicesInfo;

        return json_encode(['servicesInfo' => $servicesInfo]);
    }

    /**
     * @param string $instanceName
     *
     * @return bool
     */
    private function isProd($instanceName)
    {
        return stristr($instanceName, '-prod') !== false;
    }
}

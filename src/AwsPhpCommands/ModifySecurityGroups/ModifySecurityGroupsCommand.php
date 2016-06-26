<?php

/*
 * This file is part of the AwsPhpCommands package.
 *
 * (c) Gadelkareem <gadelkareem.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AwsPhpCommands\ModifySecurityGroups;

use Aws\Ec2\Ec2Client;
use Aws\Ec2\Exception\Ec2Exception;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Class ModifySecurityGroupsCommand
 * @package AwsPhpCommands\ModifySecurityGroups
 */
class ModifySecurityGroupsCommand extends Command
{

    /**
     * @var Ec2Client
     */
    private $awsClient;

    /**
     * @var InputInterface
     */
    private $input;

    /**
     * @var OutputInterface
     */
    private $output;

    /**
     * @var array
     */
    private $securityGroups = [];

    /**
     * @var array
     */
    private $envTypes = ["dev", "prod"];

    /**
     * @var string
     */
    private $operation;

    /**
     * @var string
     */
    private $cidr;

    /**
     * @var string
     */
    private $env;


    protected function configure()
    {
        $this->setName('aws:security-groups:modify')
            ->setDescription('Adds/removes CIDRs to security groups.')
            ->addOption(
                'cidr',
                'c',
                InputOption::VALUE_REQUIRED,
                'CIDR ex: 64.18.0.0/20',
                false
            )->addOption(
                'operation',
                'o',
                InputOption::VALUE_REQUIRED,
                'Operation to perform, one of add or remove',
                'add'
            )->addOption(
                'env',
                'e',
                InputOption::VALUE_OPTIONAL,
                'Which security groups this should run on. One of prod, dev',
                'dev'
            );

    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     */
    private function setup(InputInterface $input, OutputInterface $output)
    {
        $this->input = $input;
        $this->output = $output;

        if (!getenv('AWS_ACCESS_KEY_ID') || !getenv('AWS_SECRET_ACCESS_KEY')) {
            throw new \InvalidArgumentException("No AWS keys found! please add your AWS keys to your environment variables.");
        }

        if (!preg_match('`([0-9]{1,3}\.){3}[0-9]{1,3}\/32`', $this->input->getOption("cidr"))) {
            throw new \InvalidArgumentException("Invalid CIDR! please use this format 64.18.0.0/20");
        }
        $this->cidr = $this->input->getOption("cidr");

        if (!in_array($this->input->getOption("operation"), ['add', 'remove'])) {
            throw new \InvalidArgumentException("Invalid operation. Please use one of add or remove");
        }
        $this->operation = $this->input->getOption("operation");

        if (!in_array($this->input->getOption("env"), $this->envTypes)) {
            throw new \InvalidArgumentException("Invalid env. Please use one of " .
                implode(',', $this->envTypes)
            );
        }
        $this->env = $this->input->getOption("env");

        $config = [
            'version' => '2015-10-01',
            'region' => 'eu-west-1',
            'credentials' => [
                'key' => getenv('AWS_ACCESS_KEY_ID'),
                'secret' => getenv('AWS_SECRET_ACCESS_KEY'),
            ],
            'retries' => 0,
        ];
        $this->awsClient = new Ec2Client($config);
    }


    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->setup($input, $output);
        $this->getSecurityGroups();

        foreach ($this->securityGroups as $id => $name) {
            if (strstr($name, "prod") !== false && $this->env == 'dev') {
                continue;
            }
            $args = [
                'GroupName' => $name,
                'GroupId' => $id,
                'IpPermissions' => [
                    [
                        'IpProtocol' => '-1',
                        'IpRanges' => [['CidrIp' => $this->cidr]],
                    ],
                ],
            ];
            if ($this->operation == 'add') {
                $this->addCidr($args);
            } else {
                $this->removeCidr($args);
            }
            $this->output->writeln("- Rule {$this->operation}ed - {$name}.");
            sleep(2);
        }
        $this->output->writeln("- Found " . count($this->securityGroups) . " Security Groups.");
    }


    /**
     * @return array
     */
    private function getSecurityGroups()
    {
        $this->securityGroups = [];
        $securityGroups = $this->awsClient->describeSecurityGroups()->toArray();
        foreach ($securityGroups['SecurityGroups'] as $securityGroup) {
            $this->securityGroups[$securityGroup['GroupId']] = $securityGroup['GroupName'];
        }
        return $this->securityGroups;
    }

    /**
     * @param array $args
     */
    private function addCidr($args)
    {
        try {
            $this->awsClient->authorizeSecurityGroupIngress($args);
            $this->awsClient->authorizeSecurityGroupEgress($args);
        } catch (Ec2Exception $e) {
            $this->output->writeln("- " . $e->getMessage());
        }

    }

    /**
     * @param array $args
     */
    private function removeCidr($args)
    {
        try {
            $this->awsClient->revokeSecurityGroupIngress($args);
            $this->awsClient->revokeSecurityGroupEgress($args);
        } catch (Ec2Exception $e) {
            $this->output->writeln("- " . $e->getMessage());
        }
    }


}

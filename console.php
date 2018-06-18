#!/usr/bin/env php
<?php
/*
 * This file is part of the AwsPhpCommands package.
 *
 * (c) Gadelkareem <gadelkareem.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

define('ROOT_DIR', realpath(dirname(__FILE__)));
define('DATA_DIR', ROOT_DIR.'/data');
define('KEYS_DIR', ROOT_DIR.'/keys');

define('APP_ENV', getenv('APP_ENV'));

require ROOT_DIR.'/vendor/autoload.php';
use AwsPhpCommands\ModifySecurityGroups\ModifySecurityGroupsCommand;
use AwsPhpCommands\ServiceDiscovery\ServiceDiscoveryCommand;
use Symfony\Component\Console\Application;

ini_set('display_startup_errors', 1);
ini_set('display_errors', 1);
error_reporting(-1);

$application = new Application('AWS PHP Cli', '0.1');

$application->add(new ServiceDiscoveryCommand());
$application->add(new ModifySecurityGroupsCommand());

$application->run();

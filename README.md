
# EC2_SCHEDULER
[![Build Status](https://travis-ci.org/cpoma/ec2_scheduler.svg?branch=master)](https://travis-ci.org/github/cpoma/ec2_scheduler)

This is a "simple" yet feature filled Python 3 module that will allow you to 
stop and start EC2 instances on a schedule using TAGS associated with your EC2
instance. It will by default iterate over ALL regions available in the AWS 
platform you are on. (i.e. AWS Commercial, AWS GovCloud, .... etc ). It can be 
run on the commandline or with ENVAR values to authenticate to AWS. It is 
designed to run as a CRON job itself on a t3.nano or other instance that you 
know will be left running in your VPC at all times. 

The time for the TAGS uses the generic Linux CRON format: 

CLAP_OFF set to 51 16 * * *

Here is a quick cheat sheet on CRON formatting: 
https://crontab.guru/examples.html

If you would like the system to IGNORE the CLAP_ON or CLAP_OFF set the value to 
IGNORE.

CLAP_ON set to IGNORE (i.e. never turn on the node)
CLAP_OFF set to IGNORE (i.e. never turn off the node)

It is fairly common to set CLAP_OFF to a time, but CLAP_ON to ignore.
This allows for your to manual start the node, but provides a consistent
off time for the node.

The CLAP_OFF set to 51 16 * * *

Would map to a stop time of your server of 4:51pm each day of the week.
The code allows for a "fuzzy_minutes" windows by default of 10 minutes. It
will stop servers that should have been stopped between NOW and
(-)fuzzy_minutes ago. It will start server that should have started
between NOW and (+)fuzzy_minutes in the future. 

Yes - it starts the servers "early" by fuzzy_minutes amount since it is 
expected to run as a CRON job itself on your "scheduling" server.

The TAGS need to be on each EC2 instance in CRON format:

* CLAP_ON - The start time of your instance
* CLAP_OFF - the stop time of your instance

By default - the module runs in "DRYRUN" mode. Meaning no changes will be made. 
You need to explicitly specify 

<code>-d 0</code> or <code>--dryrun 0</code>

to turn off "DRYRUN" mode and have it actually run and change the instance state.

The ENVAR variables it will read in are:
* AWS_ACCESS_KEY_ID - Specifies an AWS access key associated with an IAM user 
or role.
* AWS_SECRET_ACCESS_KEY - Specifies the secret key associated with the access 
key. This is essentially the "password" for the AWS_ACCESS_KEY_ID key.
* AWS_SESSION_TOKEN - Specifies the session token value that is required if you 
are using temporary security credentials that you retrieved directly from AWS 
STS operations.

If the user running the code has a ~/.aws/credentials file. The authenticators located
in that file will be used.

You can "filter" the nodes the schedule tool attempts to turn off/on by
using the <code>-n, --name_filter</code> commandline options.

On the commandline you can specify the following options:

<pre>
    <code>
    [root@localhost ec2-scheduler]# ./ec2_scheduler.py --help
    Usage: ec2_scheduler.py [OPTIONS]
    
    Options:
      -i, --iam_role TEXT              Specifies the IAM Role name to use with AWS STS
                                       operations
    
      -r, --aws_region TEXT            Specifies the AWS Region to send the initial
                                       connect request  [required]
    
      -l, --limit_regions TEXT         Specifies the limited set of AWS Regions to
                                       inspect as a comma separated list

      -k, --verify_certificate BOOLEAN Ignore certificate verification for SSL 
                                       connection to AWS? - True (1) or False (0).
                                       Default: True (1)
    
      -a, --access_key TEXT            Specifies an AWS access key associated with an
                                       IAM user orrole.  [required]
    
      -s, --secret_key TEXT            Specifies the secret key associated with the
                                       access key. This is essentially the "password"
                                       for the AWS_ACCESS_KEY_ID key.  [required]
    
      -t, --session_token TEXT         Specifies the session token value that is
                                       required if you are using temporary security
                                       credentials that you retrieved directly from
                                       AWS STS operations.
    
      -d, --dryrun BOOLEAN             Is this a DryRun - True (1) or False (0)
                                       [required]
    
      -n, --name_filter TEXT           Allows for filtering to EC2 instances that have
                                       a name matching the specified string
    
      -m, --fuzzy_minutes INTEGER      Fuzzy Minutes window to act on CRON actions -
                                       Default 10  minutes.  [required]
    
      -V, --verbose BOOLEAN            True (1) of False (0) - Should STDOUT data be
                                       provided. Default: False. Details of run are
                                       logged in /var/log/ec2-scheduler.log
                                       [required]
    
      --help                           Show this message and exit.

    </code>
</pre>

## NOTE ON OTHER SCHEDULERS
Yes - AWS offers a number of other ways to do scheduling built-in. These vary 
in complexity, use of RDS, use of LAMBDA, etc.... this schedule tool is 
"simple" it does what you need without added extra cost and complexity. You can
use the other schedulers if they better suite your needs or pocketbook :-)

For more info on these other options see:
* (Legacy) https://github.com/amazon-archives/ec2-scheduler
* (Current) https://github.com/awslabs/aws-instance-scheduler
* (Current) https://aws.amazon.com/solutions/implementations/instance-scheduler/

## Example Run
<pre>
    <code>
    [root@localhost ec2-scheduler]# ./ec2_scheduler.py -d 0 -V 1
    Examining eu-north-1:
         - No instances found in eu-north-1
    Examining ap-south-1:
         - No instances found in ap-south-1
    Examining eu-west-3:
         - No instances found in eu-west-3
    Examining eu-west-2:
    |-------------------|------------------------|-------------|---------|--------------|-------------|--------------|--------------|
    |Instance ID        |Instance Name           |Instance Type|Region   |Instance State|Start Time   |Stop Time     |Current Action|
    |===============================================================================================================================|
    |i-0287312890aghse4e|EU_NODE_1               |m5.2xlarge   |eu-west-2|running       |0 7 * * 1-5 *|0 22 * * 1-5 *|None          |
    |-------------------|------------------------|-------------|---------|--------------|-------------|--------------|--------------|
    |i-0342246923889023a|EU_NODE_2               |a1.small     |eu-west-2|running       |13 19 * * *  |0 21 * * *    |Stopping Node |
    |-------------------|------------------------|-------------|---------|--------------|-------------|--------------|--------------|
    
    Examining eu-west-1:
         - No instances found in eu-west-1
    Examining ap-northeast-2:
         - No instances found in ap-northeast-2
    Examining ap-northeast-1:
         - No instances found in ap-northeast-1
    Examining sa-east-1:
         - No instances found in sa-east-1
    Examining ca-central-1:
         - No instances found in ca-central-1
    Examining ap-southeast-1:
         - No instances found in ap-southeast-1
    Examining ap-southeast-2:
         - No instances found in ap-southeast-2
    Examining eu-central-1:
         - No instances found in eu-central-1
    Examining us-east-1:
    |-------------------|------------------------|-------------|---------|--------------|-------------|--------------|--------------|
    |Instance ID        |Instance Name           |Instance Type|Region   |Instance State|Start Time   |Stop Time     |Current Action|
    |===============================================================================================================================|
    |i-095123c42df9dae4e|A_Different_Node        |t3.xlarge    |us-east-1|running       |0 7 * * 1-5 *|0 22 * * 1-5 *|None          |
    |-------------------|------------------------|-------------|---------|--------------|-------------|--------------|--------------|
    |i-03422467ed300db9a|SampleNode              |t2.nano      |us-east-1|running       |13 19 * * *  |0 19 * * *    |None          |
    |-------------------|------------------------|-------------|---------|--------------|-------------|--------------|--------------|
    
    Examining us-east-2:
         - No instances found in us-east-2
    Examining us-west-1:
         - No instances found in us-west-1
    Examining us-west-2:
         - No instances found in us-west-2
    </code>
</pre>	 

## Installation
There is a <code>requirements.txt</code> file that you can use to install the 
required Python 3 modules that support this module.

## AWS IAM Role
The following JSON Policy can be used to create a role to be used with the 
EC2_SCHEDULER code. The below policy will allow for stopping/starting of all
EC2 instances in your account. It will also allow for addition/removal of
Security Groups from an EC2 instance (this is to be used in a future 
enhancement to this code)

Attaching this Role to the EC2 instance you run the schedule on, will allow you 
to use Temporary IAM permissions to execute this code, versus a dedicated IAM
user.

For more information see: 
* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html

<pre><code>
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSecurityGroupReferences",
                "ec2:DescribeStaleSecurityGroups",
                "ec2:DescribeRegions"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:StartInstances",
                "ec2:StopInstances"
            ],
            "Resource": [
                "arn:aws:ec2:*:*:instance/*",
                "arn:aws:ec2:*:*:security-group/*"
            ],
            "Effect": "Allow"
        }
    ]
}
</code></pre>

## Running as a CRON Task
Create a file <code>/etc/cron.d/ec2-scheduler</code> with the following content (I'm restricting to US-EAST-1 in this template and using a IAM Role):
<pre>
# Run EC2-Scheduler every 10 minutes against just the US-EAST-1 region
*/10 * * * * root COLUMNS=150 /usr/bin/env python3 /path/to/ec2_scheduler.py -i "role_name or use the -a -s -t options" -l "us-east-1" -d 0
</pre>

This will run every 10 minutes and write to the log file <code>/var/log/ec2-scheduler.log</code> or <code>C:/temp/ec2-scheduler.log</code> (on Windows). Keep that in mind - this will consume disk space. On Linux - you can setup log rotate to minimize the disk space this consumes. Here is an example <code>/etc/logrotate.d/ec2-scheduler</code> file to reduce disk consumption.

<pre>
/var/log/ec2-scheduler.log {
  daily
  size 100K
  maxsize 100K
  rotate 5
  create 644 root root
  missingok
  compress
  notifempty
  copytruncate
}
</pre>

This will keep the last 5 rotations worth of logs and rotate at 100K (if you setup logrotate to run more than daily and the log is greater than 100K)

## Contributing

See CONTRIBUTING.md

Feel free to:
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request 

## History
See CHANGES.md

## Credits
[Craig Poma](https://github.com/cpoma)

## License
Apache License 2.0
#!/bin/python3
"""
__filename__ = "ec2_scheduler.py"
__author__ = "Craig Poma"
__credits__ = ["Craig Poma"]
__license__ = "Apache License 2.0"
__version__ = "1.0.0"
__maintainer__ = "Craig Poma"
__email__ = "cpoma@mitre.org"
__status__ = "Baseline"

See the requirements.txt file to install libraries for Python 3 this code
requires.

"""

# Standard Imports
import datetime
import json
import logging
import re
import sys
# Third Party Imports
import click
from croniter import croniter, CroniterNotAlphaError, CroniterBadCronError,\
    CroniterBadDateError
import boto3
import botocore
from columnar import columnar
import requests


#
# Simple dictionary to define the colors to highlight EC2 Status when printing
# the Instances found. The "columnar" natively supports this but it is broken
# in Python 3 so we are using ASCII Escape codes.
#
BCOLORS = {
    'OKBLUE' : '\033[34m',
    'OKGREEN' : '\033[32m',
    'OKRED' : '\033[31m',
    'WARNING' : '\033[93m',
    'FAIL' : '\033[91m',
    'ENDC' : '\033[0m',
    'BOLD' : '\033[1m',
    'UNDERLINE' : '\033[4m'
}

HEADERS = ["Instance ID", "Instance Name", "Instance Type",
           "Region", "Instance State", "Start Time",
           "Stop Time", "Current Action"]

IAM_URL = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'

def dry_run_warning(dryrun=None, verbose=None, logger=None):
    """
    Prints out the Dry Run Warning
    """
    if dryrun:
        logger.warning("\n\n\n" + '*'*50
                       + f"\n\t{BCOLORS['BOLD']}{BCOLORS['OKRED']}NO ACTIONS WILL HAPPEN - DRY RUN MODE\n"
                       + f"{BCOLORS['ENDC']}" + '*'*50 + '\n')
        if verbose:
            print("\n\n\n" + '*'*50
                  + f"\n\t{BCOLORS['BOLD']}{BCOLORS['OKRED']}NO ACTIONS WILL HAPPEN - DRY RUN MODE\n"
                  + f"{BCOLORS['ENDC']}" + '*'*50 + '\n')

def perform_action(schedule, now, fuzzy_seconds, logger):
    """
    Fuzzy time scheduler to determine if action should be taken to start or
    stop an instance. It takes the "fuzzy" amount of seconds and decides if
    the cron schedule (schedule) falls between now and now + seconds(passed in)
    """
    try:
        if schedule == 'IGNORE':
            # DO NOTHING
            time_to_act = False
        else:
            cron = croniter(schedule, now)
            date_plus_delta = now + datetime.timedelta(0, fuzzy_seconds)
            if fuzzy_seconds > 0:
                tag_scheduled_time = cron.get_next(datetime.datetime)
                time_to_act = (now < tag_scheduled_time < date_plus_delta)
            else:
                tag_scheduled_time = cron.get_prev(datetime.datetime)
                time_to_act = (date_plus_delta < tag_scheduled_time < now)
            logger.info("now %s" % now)
            logger.info("date_plus_delta %s" % date_plus_delta)
            logger.info("tag_scheduled_time %s" % tag_scheduled_time)
    except CroniterNotAlphaError as cron_exception:
        time_to_act = False
        logger.error('Exception error CroniterNotAlphaError: %s' \
                     % (cron_exception))
        print('Exception error CroniterNotAlphaError: %s' % (cron_exception))
    except CroniterBadDateError as cron_exception:
        time_to_act = False
        logger.error('Exception error CroniterBadDateError: %s' \
                     % (cron_exception))
        print('Exception error CroniterBadDateError: %s' % (cron_exception))
    except CroniterBadCronError as cron_exception:
        time_to_act = False
        logger.error('Exception error CroniterBadCronError: %s' \
                     % (cron_exception))
        print('Exception error CroniterBadCronError: %s' % (cron_exception))

    return time_to_act

def process_stop_instances(stop_instance_list=None, aws_ec2_client=None,
                           region=None, dryrun=None, logger=None):
    """ Will stop the instances based on their CLAP_OFF time"""
    if len(stop_instance_list) > 0:
        try:
            response = aws_ec2_client.stop_instances(
                InstanceIds=stop_instance_list, DryRun=dryrun)
            # print("aws_ec2_client.start_instances %s" % response)
            logger.info('Stopping Instances %s', response)
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'DryRunOperation':
                logger.warning('DryRun Mode set - no action performed')
            else:
                logger.error('Exception error in %s: %s' % (region, error))
                print('Exception error in %s: %s' % (region, error))

def process_start_instances(start_instance_list=None, aws_ec2_client=None,
                            region=None, dryrun=None, logger=None):
    """ Will start the instances based on their CLAP_ON time"""
    if len(start_instance_list) > 0:
        try:
            response = aws_ec2_client.start_instances(
                InstanceIds=start_instance_list, DryRun=dryrun)
            # print("aws_ec2_client.start_instances %s" % response)
            logger.info('Starting Instances %s', response)
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'DryRunOperation':
                logger.warning('DryRun Mode set - no action performed')
            else:
                logger.error('Exception error in %s: %s' % (region, error))
                print('Exception error in %s: %s' % (region, error))


def init_connection(aws_region=None, limit_regions=None, access_key=None,
                    secret_key=None, session_token=None, iam_role=None,
                    logger=None, verbose=None):
    """
    Setup the initial connection parameters for AWS
    """
    init_config = {
        'access_key': access_key,
        'secret_key': secret_key,
        'session_token': session_token,
        'ec2_regions': aws_region
    }

    try:

        seed_data = seed_iam_values(iam_role=iam_role, logger=logger,
                                    verbose=verbose)
        if seed_data['seeded']:
            access_key = seed_data['access_key']
            secret_key = seed_data['secret_key']
            session_token = seed_data['session_token']

        aws_ec2_client = boto3.client('ec2',
                                      region_name=aws_region,
                                      aws_access_key_id=access_key,
                                      aws_secret_access_key=secret_key,
                                      aws_session_token=session_token)

        if limit_regions:
            # De-duplicate using list(set()) incase user passed in same values multiple times
            ec2_regions = sorted(list(set(limit_regions.split(","))))
        else:
            ec2_regions = sorted([region['RegionName'] for region in
                                  aws_ec2_client.describe_regions()['Regions']])

        init_config = {
            'aws_ec2_client' : aws_ec2_client,
            'access_key' : access_key,
            'secret_key' : secret_key,
            'session_token' : session_token,
            'ec2_regions' : ec2_regions
        }
    except botocore.exceptions.ClientError as client_exception:
        logger.error('Exception error in: %s', client_exception)
        print('Exception error in: %s' % (client_exception))
        sys.exit()

    return init_config

def seed_iam_values(iam_role=None, logger=None, verbose=None):
    """
    Check to see of the '--iam_role', '-i' options have been used on the
    command-line. If so, attempt to pull the Role IAM credentials from AWS
    """
    iam_values = {'seeded': False}
    if iam_role:
        response = requests.get(IAM_URL + iam_role)
        if response.status_code == 200:
            response_text = response.text
            iam_values['seeded'] = True
            iam_values['access_key'] = \
                str(json.loads(response_text)['AccessKeyId'])
            iam_values['secret_key'] = \
                str(json.loads(response_text)['SecretAccessKey'])
            iam_values['session_token'] = \
                str(json.loads(response_text)['Token'])
        else:
            logger.error('Role specified (%s) not found', iam_role)
            if verbose:
                print("Role specified (%s) not found" % (iam_role))

    return iam_values


@click.command()
@click.option('--iam_role', '-i',
              default='',
              envvar='AWS_IAM_ROLE_NAME',
              required=False,
              type=str,
              help='Specifies the IAM Role name to use with AWS STS '
              + 'operations')

@click.option('--aws_region', '-r',
              default='us-east-1',
              envvar='AWS_DEFAULT_REGION',
              required=True,
              type=str,
              help='Specifies the AWS Region to send the initial connect '
              + 'request')

@click.option('--limit_regions', '-l',
              default='',
              envvar='AWS_LIMITED_REGION',
              required=False,
              type=str,
              help='Specifies the limited set of AWS Regions to inspect as a comma separated list')

@click.option('--access_key', '-a',
              default='',
              envvar='AWS_ACCESS_KEY_ID',
              required=True,
              type=str,
              help='Specifies an AWS access key associated with an IAM user or'
              + 'role.')

@click.option('--secret_key', '-s',
              default='',
              envvar='AWS_SECRET_ACCESS_KEY',
              required=True,
              type=str,
              help='Specifies the secret key associated with the access key. '
              + 'This is essentially the "password" for the AWS_ACCESS_KEY_ID '
              + 'key.')

@click.option('--session_token', '-t',
              default='',
              envvar='AWS_SESSION_TOKEN',
              required=False,
              type=str,
              help='Specifies the session token value that is required if you '
              + 'are using temporary security credentials that you retrieved '
              + 'directly from AWS STS operations.')

@click.option('--dryrun', '-d',
              default=True,
              required=True,
              type=bool,
              help='Is this a DryRun - True (1) or False (0)')

@click.option('--name_filter', '-n',
              default='',
              required=False,
              type=str,
              help='Allows for filtering to EC2 instances that have a name matching '
              + 'the specified string')

@click.option('--fuzzy_minutes', '-m',
              default=10,
              required=True,
              type=int,
              help='Fuzzy Minutes window to act on CRON actions - Default 10 '
              + ' minutes.')

@click.option('--verbose', '-V',
              default=False,
              required=True,
              type=bool,
              help='True (1) of False (0) - Should STDOUT data be provided. '
              + 'Default: False. Details of run are logged in '
              +'/var/log/ec2-scheduler.log')

def main(iam_role=None, aws_region=None, access_key=None, secret_key=None,
         session_token=None, dryrun=True, limit_regions=None,
         name_filter=None, fuzzy_minutes=10, verbose=False):
    """
    This is a "simple" yet feature filled Python 3 module that will allow you
    to stop and start EC2 instances on a schedule using TAGS associated with
    your EC2 instance. It will by default iterate over ALL regions avaliable in
    the AWS platform you are on. (i.e. AWS Commercial, AWS GovCloud, .... etc).
    It can be run on the commandline or with ENVAR values to authenticate to
    AWS. It is designed to run as a CRON job itself on a t3.nano or other
    instance that you know will be left running in your VPC at all times.

    The time for the TAGS uses the generic Linux CRON format:

    CLAP_OFF set to 51 16 * * *

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

    By default - the module runs in "DRYRUN" mode. Meaning no changes will be
    made. You need to explicitly specify

    -d 0 or --dryrun 0

    to turn off "DRYRUN" mode and have it actually run and change the instance
    state.
    """

    logger = None
    try:
        # Set up our logger
        logging.basicConfig(filename='/var/log/ec2-scheduler.log',
                            level=logging.INFO,
                            format='%(asctime)s %(levelname)s %(message)s')
        logger = logging.getLogger('ec2-scheduler')
    except PermissionError as perm_exception:
        print("\n\n\n" + '*' * 65
              + f"\n\t{BCOLORS['BOLD']}{BCOLORS['OKRED']}The logger cannot open and write to the log file.\n"
              + f"{BCOLORS['ENDC']}" + '*' * 65 + '\n')
        print('Exception error: %s' % (perm_exception))
        sys.exit()

    now = datetime.datetime.now()

    dry_run_warning(dryrun=dryrun, verbose=verbose, logger=logger)

    inital_connection = init_connection(aws_region=aws_region,
                                        limit_regions=limit_regions,
                                        access_key=access_key,
                                        secret_key=secret_key,
                                        session_token=session_token,
                                        iam_role=iam_role,
                                        logger=logger,
                                        verbose=verbose)

    for region in inital_connection['ec2_regions']:
        try:
            logger.info("Examining %s:", region)
            if verbose:
                print("Examining %s:" % region)
            conn = boto3.resource('ec2', region_name=region,
                                  aws_access_key_id=inital_connection['access_key'],
                                  aws_secret_access_key=inital_connection['secret_key'],
                                  aws_session_token=inital_connection['session_token'])

            # False Positive - so disable this finding here
            # pylint: disable=E1101
            instances = conn.instances.filter()
            # pylint: enable=E1101
            start_instance_list = []
            stop_instance_list = []
            #print (list(instances))
            if not list(instances):
                logger.info("\t - No instances found in %s", region)
                if verbose:
                    print("\t - No instances found in %s" % region)


            ec2_instance = []
            for instance in instances:
                # print("Examining instance %s:" % instance)
                instance_name = 'Unknown'
                start_sched = 'None'
                stop_sched = 'None'
                current_action = 'None'

                for tag_set in instance.tags:
                    if tag_set['Key'] == "Name" and \
                            tag_set['Value'] is not None and \
                            tag_set['Value'] != "":
                        instance_name = tag_set['Value']

                    if tag_set['Key'] == 'CLAP_ON' and \
                            tag_set['Value'] is not None and \
                            tag_set['Value'] != "":
                        start_sched = tag_set['Value']

                    if tag_set['Key'] == 'CLAP_OFF' and \
                            tag_set['Value'] is not None and \
                            tag_set['Value'] != "":
                        stop_sched = tag_set['Value']

                # Must MATCH the filter to have an action upon it
                if name_filter:
                    if not re.search(name_filter, instance_name):
                        print('Skipping due to filter (%s) - %s' % (name_filter, instance_name))
                        continue

                # Start instances if their CRON is between now and the
                # next fuzzy_minutes minutes
                if start_sched is not None and \
                        instance.state["Name"] == "stopped" and \
                        perform_action(start_sched, now, fuzzy_minutes * 60,
                                       logger):
                    start_instance_list.append(instance.id)
                    #current_action = "Starting Node"
                    current_action = f"{BCOLORS['BOLD']}{BCOLORS['OKGREEN']}" \
                                     + f"Starting Node{BCOLORS['ENDC']}"

                # Start instances if their CRON is between fuzzy_minutes ago
                # and the now
                if stop_sched is not None and \
                        instance.state["Name"] == "running" and \
                        perform_action(stop_sched, now, fuzzy_minutes * -60,
                                       logger):
                    stop_instance_list.append(instance.id)
                    #current_action = "Stopping Node"
                    current_action = f"{BCOLORS['BOLD']}{BCOLORS['OKRED']}" \
                                     + f"Stopping Node{BCOLORS['ENDC']}"


                ec2_instance.append([instance.id, instance_name,
                                     instance.instance_type, region,
                                     instance.state["Name"], start_sched,
                                     stop_sched, current_action])

            if ec2_instance:
                logger.info("\n\n %s", columnar(ec2_instance, headers=HEADERS,
                                                no_borders=False))
                if verbose:
                    print(columnar(ec2_instance, headers=HEADERS,
                                   no_borders=False))

            # Perform Start Actions
            process_start_instances(start_instance_list=start_instance_list,
                                    aws_ec2_client=inital_connection['aws_ec2_client'],
                                    region=region,
                                    dryrun=dryrun,
                                    logger=logger)

            # Perform Stop Actions
            process_stop_instances(stop_instance_list=stop_instance_list,
                                   aws_ec2_client=inital_connection['aws_ec2_client'],
                                   region=region,
                                   dryrun=dryrun,
                                   logger=logger)

        except botocore.exceptions.ClientError as region_exception:
            #pass
            logger.error('Exception error in %s: %s', region, region_exception)
            print('Exception error in %s: %s' % (region, region_exception))

if __name__ == '__main__':
    main()

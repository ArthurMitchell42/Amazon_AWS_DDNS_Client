#====================================================================================================
# AWS_Route53_DDNS Updater
#====================================================================================================
import logging
import logging.handlers
import configparser
import ipaddress
from urllib.request import Request, urlopen
from urllib.error import URLError
import botocore
import boto3
import time
import os          # For enviromnent variables
import pathlib     # For file touching
import json        # For webhooks
import re          # From the text cleaning functions

#====================================================================================================
# Global definitions and environment variables
#====================================================================================================
try:
    File_Paths = os.environ['AWS_CONFIG_PATH']
except KeyError: 
    print("Environment variable 'AWS_CONFIG_PATH' not found. Defaulting to CWD.")
    File_Paths = ""

if( not os.path.exists(File_Paths) ):
    print("Path {} does not exist".format(File_Paths))
    exit(1)

Healthcheck_Interval_File_Name = None
Healthcheck_Heartbeat_File_Name = None
try:
    Healthcheck_Heartbeat_File_Name = os.environ['HEALTHCHECK_HEARTBEAT_FILE']
    Heartbeat_Enabled = True
    pathlib.Path( Healthcheck_Heartbeat_File_Name ).touch()
    try:
        Healthcheck_Interval_File_Name = os.environ['HEALTHCHECK_INTERVAL_FILE']
    except KeyError: 
        Healthcheck_Interval_File_Name = None
        Heartbeat_Enabled = False
except KeyError: 
    Heartbeat_Enabled = False

Docker_Version = os.environ.get('AWS_DOCKER_VERSION', 'None')

Log_File_Name = File_Paths + "AWS_Route53_DDNS.log"
Config_File_Name = File_Paths + "AWS_Route53_DDNS.ini"
log = logging.getLogger('AWS_Route53_DDNS')

App_Version = "2.1.0.0"
Domain_Names = []
Record_Names = []
Update_Interval = 0
Exception_Interval = 0
TTL_Interval = 0
Sleep_Time_Initial_Autherisation = 0
Sleep_Time_Inter_Domain = 0
WebHook_Alive = None
WebHook_Alert = None
AWS_Access_Key_ID = None 
AWS_Secret_Access_Key = None
AWS_Credential_Profile=None

#====================================================================================================
# Call a webhook
#====================================================================================================
def Call_Webhook( Hook ):
    if not Hook:
        log.info("Webhook is not set.")
        return

    log.debug("Calling webhook {}".format(Hook))

    try:
        res = urlopen(Hook)
    except URLError as e:
        if hasattr(e, 'reason'):
            log.warning("Failed to call webhook. Reason: %s", e.reason)
        elif hasattr(e, 'code'):
            log.warning("The webhook server could't fulfill the request. Error code: %s", e.code)
        return
    else:
        resp = res.getcode()
        if resp != 200:
            log.warning("The webhook call returned code: ", resp)

        page = res.read()
        data_json = json.loads(page)
        
        if ("ok" in data_json):
            if (data_json["ok"] != True):
                if ("msg" in data_json):
                    jmsg = data_json["msg"]
                else:
                    jmsg = "none"
                log.warning("The webhook returned an 'ok' element as not True with the message '{}'".format(jmsg))
    return True

#====================================================================================================
# Set up logging
#====================================================================================================
log.setLevel(logging.DEBUG)

# Setup logging to a file
logfile = logging.handlers.RotatingFileHandler(Log_File_Name, maxBytes=100000, backupCount=5)
logfile.setLevel(logging.DEBUG)

# Setup logging to the console
logcons = logging.StreamHandler()
logcons.setLevel(logging.DEBUG)

# Define the format of the log information
logform = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s') #  %(name)s
logfile.setFormatter(logform)
logcons.setFormatter(logform)
log.addHandler(logfile)
log.addHandler(logcons)

#====================================================================================================
# AWS Services functions
#====================================================================================================
def Check_DNS_Response(Route53_Client, Hosted_Zone_Id, Record_Name):
    try:
        resp = Route53_Client.test_dns_answer( 
            HostedZoneId=Hosted_Zone_Id,
            RecordName=Record_Name,
            RecordType='A'
            )
    except Route53_Client.exceptions.InvalidInput as e:
        log.error("Error finding {} in zone {}. Error: {}".format(Record_Name, Hosted_Zone_Id, e))
        return

    if resp['ResponseCode'] != 'NOERROR': 
        log.warning("DNS Response is in error for {} {}.".format(Record_Name, Hosted_Zone_Id))
        return

    recname = resp['RecordName']
    recdata = resp['RecordData']

    if recname != Record_Name: 
        log.warning("The record name does not match when checking the DNS response.")
        return

    try:
        IP_Address = ipaddress.IPv4Address(recdata[0])
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
        log.error("Can't recognise the external IP address response: {}".format(e))
        return
    else: return IP_Address

#====================================================================================================
# Return IP of a record
#====================================================================================================
def Get_DNS_Record_IP(Route53_Client, Zone_ID, Record_Name):
    # List all the record sets for a zone
    resp = Route53_Client.list_resource_record_sets( 
        HostedZoneId=Zone_ID,  
        StartRecordName=Record_Name,
        StartRecordType='A',
        MaxItems='100'
        )

    for i in resp['ResourceRecordSets']:
        if i['Name'] == Record_Name:
            addr_str = i['ResourceRecords'][0]['Value']
            try:
                address = ipaddress.IPv4Address(addr_str)
                return address
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
                log.error("Can't recognise the external IP address response: {}".format(e))
                return
    return

#====================================================================================================
# Return the Hosted_Zone_Id from the Domain_Name
#====================================================================================================
def Find_Hosted_Zone_Id(Route53_Client, Domain_Name):
    # List all the hosted zones for a user
    try:
        zones = Route53_Client.list_hosted_zones_by_name()
    except botocore.exceptions.ClientError as error:
        log.warning("Could not list zones: %s", error)
        return
    except botocore.exceptions.NoCredentialsError as error:
        log.critical("Could not list zones: %s", error)
        return

    if zones['IsTruncated'] == 'True':
        log.error("Can't handle truncated zone lists in {}".format(Domain_Name))
        return

    Hosted_Zone_Id = None
    for index in range(0,len(zones['HostedZones'])):
        if zones['HostedZones'][index]['Name'] == Domain_Name:
            Hosted_Zone_Id = zones['HostedZones'][index]['Id']
            break
    
    return Hosted_Zone_Id

#====================================================================================================
# Change a record set
#====================================================================================================
def Update_DNS_Record_IP(Route53_Client, Hosted_Zone_Id, Record_Name, New_IP, TTL_Interval ):
    ChangeBatch_Dict = {
        'Changes': [
                {
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': Record_Name,
                    'ResourceRecords': [ { 'Value': str(New_IP), }, ],
                    'TTL': TTL_Interval,
                    'Type': 'A',
                    },
                },
            ],
        }

    log.info("Updating {} {} with new address {}".format(Hosted_Zone_Id, Record_Name, str(New_IP)))
    change = Route53_Client.change_resource_record_sets( 
        ChangeBatch  = ChangeBatch_Dict,
        HostedZoneId = Hosted_Zone_Id,        
        )
    
    if int(change['ResponseMetadata']['HTTPStatusCode']) == 200: return True
    return False

#====================================================================================================
# IP Services - Get the external IP address with error checking and return it.
#====================================================================================================
def Get_External_IP_From_AWS():
    req = Request('http://checkip.amazonaws.com')

    try:
        res = urlopen(req)
    except URLError as e:
        if hasattr(e, 'reason'):
            log.warning("Failed to reach AWS IP checking server. Reason: %s", e.reason)
        elif hasattr(e, 'code'):
            log.warning("The AWS IP checking server couldn't fulfil the request. Error code: %s", e.code)
        return
    except Exception as e:
        if hasattr(e, 'reason'):
            log.warning("Failed to reach AWS IP checking server. Reason: %s", e.reason)
        elif hasattr(e, 'code'):
            log.warning("The AWS IP checking server couldn't fulfil the request. Error code: %s", e.code)
        return
    else:
        page = res.read()
        page = page[0:len(page)-1].decode('utf-8')
        try:
            address = ipaddress.IPv4Address(page)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
            log.warning("Can't recognise the external IP address response: {}".format(e))
            return

        return address

#====================================================================================================
# If health checking is enabled, update the file that conveys the update interval to the 
# shell script.
#====================================================================================================
def Write_Interval(Update_Interval):
    global Healthcheck_Interval_File_Name
    global Heartbeat_Enabled

    if not Heartbeat_Enabled:
        return

    Health_Interval = Update_Interval + int( float(Update_Interval) / 20.0)        

    if Healthcheck_Interval_File_Name:
        try:
            open(Healthcheck_Interval_File_Name, 'w')
            with open(Healthcheck_Interval_File_Name, 'w') as f:
                f.write(str(Health_Interval))
        except Exception as e:
            log.error("Can't write to update interval file: {}".format(Healthcheck_Interval_File_Name))

    log.debug("Updating health check interval to: {} seconds".format(Health_Interval))
    return

#====================================================================================================
# Read the app configuration from the .INI file.
#====================================================================================================
def Read_Configuration():
    global Domain_Names
    global Record_Names
    global Update_Interval
    global Exception_Interval
    global TTL_Interval
    global Sleep_Time_Initial_Autherisation
    global Sleep_Time_Inter_Domain
    global WebHook_Alert
    global WebHook_Alive
    global AWS_Access_Key_ID 
    global AWS_Secret_Access_Key
    global AWS_Credential_Profile

    config = configparser.ConfigParser()
    try:
        config.read(Config_File_Name)
    except Exception as err:
        log.critical("Exception reading configuration file {}".format(err))

# Check that the 'Domains' section is present in the config file:
    if not config.has_section('Domains'):
        log.critical("Domain section not found in the configuration file.")
        return

# Check what the logging levels are to be in the configuration file
    if config.has_option('Defaults', 'Log_Level_Logfile'):
        level = config['Defaults']['Log_Level_Logfile'].lower()
        if    level == 'debug'    : logfile.setLevel(logging.DEBUG)
        elif  level == 'info'     : logfile.setLevel(logging.INFO)
        elif  level == 'warning'  : logfile.setLevel(logging.WARNING)
        elif  level == 'error'    : logfile.setLevel(logging.ERROR)
        elif  level == 'critical' : logfile.setLevel(logging.CRITICAL)
        else: log.error("Logfile error level %s not recognised in Defaults section of configuration file.", level)
    else:
        logfile.setLevel(logging.WARNING)

    if config.has_option('Defaults', 'Log_Level_Console'):
        level = config['Defaults']['Log_Level_Console'].lower()
        if    level == 'debug'    : logcons.setLevel(logging.DEBUG)
        elif  level == 'info'     : logcons.setLevel(logging.INFO)
        elif  level == 'warning'  : logcons.setLevel(logging.WARNING)
        elif  level == 'error'    : logcons.setLevel(logging.ERROR)
        elif  level == 'critical' : logcons.setLevel(logging.CRITICAL)
        else: log.error("Logfile error level %s not recognised in Defaults section of configuration file.", level)
    else:
        logfile.setLevel(logging.ERROR)

# Extract the zone (domain) names and record names
    if len(config.options('Domains')) == 0:
        log.critical("No list of domains found the the Domains section of configuration file.")
        return

    Domain_Names = []
    Record_Names = []
    for l in config.options('Domains'):
        Domain_Names.append(l) 
        Record_Names.append(config['Domains'][l]) 
    
    if config.has_option('Defaults', 'Update_Interval'):
        Update_Interval = int(config['Defaults']['Update_Interval'])
        if Update_Interval < 30: Update_Interval = 30
    else:
        Update_Interval = 7200

    if config.has_option('Defaults', 'Exception_Interval'):
        Exception_Interval = int(config['Defaults']['Exception_Interval'])
        if Exception_Interval < 30: Exception_Interval = 30
    else:
        Exception_Interval = Update_Interval

    if config.has_option('Defaults', 'ttl'):
        TTL_Interval = int(config['Defaults']['ttl'])
        if TTL_Interval < 60: TTL_Interval = 60
    else:
        TTL_Interval = 3600

    if config.has_option('Defaults', 'Sleep_Time_Initial_Autherisation'):
        Sleep_Time_Initial_Autherisation = int(config['Defaults']['Sleep_Time_Initial_Autherisation'])
        if Sleep_Time_Initial_Autherisation < 1: Sleep_Time_Initial_Autherisation = 1
    else:
        Sleep_Time_Initial_Autherisation = 1

    if config.has_option('Defaults', 'Sleep_Time_Inter_Domain'):
        Sleep_Time_Initial_Autherisation = int(config['Defaults']['Sleep_Time_Inter_Domain'])
        if Sleep_Time_Inter_Domain < 1: Sleep_Time_Inter_Domain = 1
    else:
        Sleep_Time_Inter_Domain = 1

    if config.has_option('Defaults', 'Webhook_Alive'):
        WebHook_Alive = config['Defaults']['Webhook_Alive']
        if (WebHook_Alive[0] == "'" and WebHook_Alive[-1] == "'") or \
           (WebHook_Alive[0] == '"' and WebHook_Alive[-1] == '"'):
            WebHook_Alive = WebHook_Alive[1:-1]

    if config.has_option('Defaults', 'Webhook_Alert'):
        WebHook_Alert = config['Defaults']['Webhook_Alert']
        if (WebHook_Alert[0] == "'" and WebHook_Alert[-1] == "'") or \
           (WebHook_Alert[0] == '"' and WebHook_Alert[-1] == '"'):
            WebHook_Alert = WebHook_Alert[1:-1]

#====================================================================================================
# See if the config file contains the AWS access keys
#====================================================================================================
    if config.has_option('Credentials', 'aws_access_key_id') and config.has_option('Credentials', 'aws_secret_access_key'):
        AWS_Access_Key_ID = config['Credentials']['AWS_Access_Key_ID']
        AWS_Secret_Access_Key = config['Credentials']['AWS_Secret_Access_Key']

        if (AWS_Access_Key_ID[0] == "'" and AWS_Access_Key_ID[-1] == "'") or \
           (AWS_Access_Key_ID[0] == '"' and AWS_Access_Key_ID[-1] == '"'):
            AWS_Access_Key_ID = AWS_Access_Key_ID[1:-1]
 
        if (AWS_Secret_Access_Key[0] == "'" and AWS_Secret_Access_Key[-1] == "'") or \
           (AWS_Secret_Access_Key[0] == '"' and AWS_Secret_Access_Key[-1] == '"'):
            AWS_Secret_Access_Key = AWS_Secret_Access_Key[1:-1]

#====================================================================================================
# See if the config file contains the AWS credential profile
#====================================================================================================
    if config.has_option('Credentials', 'AWS_Credential_Profile'):
        AWS_Credential_Profile = config['Credentials']['AWS_Credential_Profile']
        if (AWS_Credential_Profile[0] == "'" and AWS_Credential_Profile[-1] == "'") or \
           (AWS_Credential_Profile[0] == '"' and AWS_Credential_Profile[-1] == '"'):
            AWS_Credential_Profile = AWS_Credential_Profile[1:-1]
    else:
        try:
            AWS_Credential_Profile = os.environ['AWS_PROFILE']
        except KeyError: 
            AWS_Credential_Profile = 'route53_user'

#====================================================================================================
# Write the logged update interval to the file used in the health check
#====================================================================================================
    Write_Interval(Update_Interval)

    log.debug("Domains and records loaded: {} {}".format(Domain_Names, Record_Names))
    log.debug("Interval loaded: {}".format(Update_Interval))
    log.debug("Exception interval loaded: {}".format(Exception_Interval))
    log.debug("TTL: {}".format(TTL_Interval))
    log.debug("Sleep_Time_Initial_Autherisation: {}".format(Sleep_Time_Initial_Autherisation))
    log.debug("Webhook_Alive: {}".format(WebHook_Alive))
    log.debug("Webhook_Alert: {}".format(WebHook_Alert))
    if( AWS_Access_Key_ID and AWS_Secret_Access_Key ):
        log.debug("AWS Access keys set from config file")
    return

#====================================================================================================
# Main function
#====================================================================================================
def main():
    global AWS_Access_Key_ID 
    global AWS_Secret_Access_Key

    log.info("Program starting. App version is {}, docker container version is {}".format(App_Version, Docker_Version))

#====================================================================================================
# Read the configuration file
#====================================================================================================
    if not os.path.isfile(Config_File_Name):
        log.critical("Configuration file {} not found.".format(Config_File_Name))
        return

    Config_File_Moddate = os.stat(Config_File_Name)[8]
    Config_File_Previous_Timestamp = time.ctime(Config_File_Moddate)

    Read_Configuration()

#====================================================================================================
# Try to set up the AWS session object from the credientials file or environment variables
#   1. Check if credentials were found in the config file
#   2. Check if the credentials were set as environment variables
#   3. Check for the _FILE environment variables and load from them if present 
#   4. Try to get credentials from the default credentials file
#====================================================================================================
#========================================
# Option 1
#========================================
    if( AWS_Access_Key_ID and AWS_Secret_Access_Key ):
        try:
            Route53_Session = boto3.Session(aws_access_key_id=AWS_Access_Key_ID, aws_secret_access_key=AWS_Secret_Access_Key )
            log.debug("Credentials from config file created a session.")
        except Exception as error:
            log.info("Credentials from config file failed to create a session. %s", error)
            exit(1)
    else:
#========================================
# Option 2
#========================================
        Found_ID_Env_Var = False
        Found_Secret_Env_Var = False

        try:
            AWS_Access_Key_ID = os.environ['AWS_ACCESS_KEY_ID']
            Found_ID_Env_Var = True
        except KeyError: 
            Found_ID_Env_Var = False

        try:
            AWS_Secret_Access_Key = os.environ['AWS_SECRET_ACCESS_KEY']
            Found_Secret_Env_Var = True
        except KeyError: 
            Found_Secret_Env_Var = False

        if Found_ID_Env_Var and Found_Secret_Env_Var:
            try:
                Route53_Session = boto3.Session()
                log.debug("Credentials from environment variables successfully created a session.")
            except Exception :
                log.info("Environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY found but didn't create a session successfully.")
                exit(1)
        else:
            log.debug("Environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY not found.")
#========================================
# Option 3
#========================================
            Found_ID_Env_Var = False
            Found_Secret_Env_Var = False
            try:
                AWS_Access_Key_ID_File_Name = os.environ['AWS_ACCESS_KEY_ID_FILE']
                Found_ID_Env_Var = True
            except KeyError: 
                Found_ID_Env_Var = False

            try:
                AWS_Secret_Access_Key_File_Name = os.environ['AWS_SECRET_ACCESS_KEY_FILE']
                Found_Secret_Env_Var = True
            except KeyError: 
                Found_Secret_Env_Var = False

            if Found_ID_Env_Var and Found_Secret_Env_Var:
                try:
                    with open(AWS_Access_Key_ID_File_Name, 'r') as f:
                        AWS_Access_Key_ID = f.readline()
                except Exception as e:
                    log.error("Can't read AWS_ACCESS_KEY_ID_FILE file: {}".format(AWS_Access_Key_ID_File_Name))
                    exit(1)
                try:
                    with open(AWS_Secret_Access_Key_File_Name, 'r') as f:
                        AWS_Secret_Access_Key = f.readline()
                except Exception as e:
                    log.error("Can't read AWS_SECRET_ACCESS_KEY_FILE file: {}".format(AWS_Secret_Access_Key_File_Name))
                    exit(1)

                Cleaning_Pattern = r"[ \n\r'\"]"
                AWS_Access_Key_ID = re.sub( Cleaning_Pattern, "", AWS_Access_Key_ID )
                AWS_Secret_Access_Key = re.sub( Cleaning_Pattern, "", AWS_Secret_Access_Key )

                log.debug("Environment variables AWS_ACCESS_KEY_ID_FILE and AWS_SECRET_ACCESS_KEY_FILE in use, keys loaded")

                try:
                    Route53_Session = boto3.Session(aws_access_key_id=AWS_Access_Key_ID , aws_secret_access_key=AWS_Secret_Access_Key )
                    log.debug("Credentials from _FILE environment variables created a session successfully.")
                except Exception :
                    log.info("Credentials from file environment variables failed to create a session.")
            else:
                log.debug("Environment variables AWS_ACCESS_KEY_ID_FILE and AWS_SECRET_ACCESS_KEY_FILE not found.")
 
#========================================
# Option 4
#========================================
                try:
                    Route53_Session = boto3.Session(profile_name=AWS_Credential_Profile)
                    log.debug("Profile {} found in credentials file.".format(AWS_Credential_Profile))
                except botocore.exceptions.ProfileNotFound :
                    log.debug("Profile {} not found in credentials file. Trying the default profile.".format(AWS_Credential_Profile))
                    try:
                        Route53_Session = boto3.Session(profile_name='default')
                        log.debug("Profile default found in credentials file.")
                    except botocore.exceptions.ProfileNotFound :
                        log.debug("Default profile not found in credentials file.")
                        log.critical("No valid AWS credentials were found. Please check the documentation for how to provide them.")
                        exit(1)

# Create the Route53 client object
    Route53_Client = Route53_Session.client( 'route53' )

# Test the credentials by listing all the hosted zones for a user
    try:
        zones = Route53_Client.list_hosted_zones_by_name()
        log.debug("Testing credentials: Successfully listed zones.")
    except botocore.exceptions.ClientError as error:
        log.error("Testing credentials: Could not list zones: %s", error)
        exit(1)
    except botocore.exceptions.NoCredentialsError as error:
        log.fatal("Testing credentials: Could not list zones with the loaded credentials: %s", error)
        exit(1)
    except botocore.exceptions.HTTPClientError as error:
        log.fatal("Testing credentials: Could not list zones with the loaded credentials: %s", error)
        exit(1)

#====================================================================================================
# Initialise a false last IP address to force an update check
#====================================================================================================
    time.sleep(Sleep_Time_Initial_Autherisation)
    Last_External_Address = "0.0.0.0"

#====================================================================================================
# The main functional loop
#====================================================================================================
    try:
        while True:
    # Find our current external IP address
            Issue_Updating = False

            External_Address = Get_External_IP_From_AWS()
            if External_Address == None:
                log.error("Could not determine the external IP address")
                Issue_Updating = True
            else:
                log.info("External IP address: {}".format(External_Address))
                if External_Address != Last_External_Address: 
                    if Last_External_Address != "0.0.0.0":
                        log.warning("External IP address has changed from {} to {}".format(Last_External_Address, External_Address))
                    Last_External_Address = External_Address
            
    # Loop round the list of domain names and records we are montioring
                for Domain_Index in range(0, len(Domain_Names)):
                    time.sleep(Sleep_Time_Inter_Domain)
                    Domain_Name_dot = Domain_Names[Domain_Index].lower() + '.'
                    Record_Name_dot = Record_Names[Domain_Index].lower() + '.'
                    log.debug("Checking domain {} for record {}".format(Domain_Name_dot, Record_Name_dot))
    # Get the hosted zone ID for the domain being checked
                    Hosted_Zone_Id = Find_Hosted_Zone_Id(Route53_Client, Domain_Name_dot)
                    if Hosted_Zone_Id == None:
                        log.error("Couldn't find hosted zone {}".format(Domain_Name_dot))
                        Issue_Updating = True
                    else:
    # Check the DNS response to see what IP address is currently answering to this record
                        DNS_Address = Check_DNS_Response( Route53_Client, Hosted_Zone_Id, Record_Name_dot )
                        if DNS_Address == None:
                            log.error("Didn't get a valid address for {} using DNS.".format(Record_Name_dot))
                            Issue_Updating = True
                        else:
                            log.debug("Current listed address for {} is {}".format(Record_Name_dot, DNS_Address))

                            if DNS_Address == External_Address:
    # If we get here then the DNS response is correctly pointing to our current external IP address
                                log.info("DNS Address matches, no change needed to {} {}".format(Domain_Name_dot, Record_Name_dot))
                            else:
    # If we get here then the DNS is not pointing to our external IP address
    # There are two options here
                                Record_IP = Get_DNS_Record_IP(Route53_Client, Hosted_Zone_Id, Record_Name_dot)
                                if Record_IP == External_Address:
    # If we get here then the DNS entry is correct but it hasn't propagated to whichever DNS server answered our query
                                    log.warning("DNS update is pending")
                                else:
    # If we get here then the DNS record needs updating, which we do and check that a HTTP 200 message is seen in the response
                                    log.info("DNS Address needs updating")
                                    if Update_DNS_Record_IP(Route53_Client, Hosted_Zone_Id, Record_Name_dot, External_Address, TTL_Interval ):
                                        log.debug("DNS update accepted")
                                    else:
                                        log.error("DNS update request was note accepted")
            
            if Issue_Updating:
                Call_Webhook( WebHook_Alert + "UpdateIssue" )
                log.warning("Sleeping for the exception interval {} seconds after an issue updating.".format(Exception_Interval))
                time.sleep(Exception_Interval)        
            else:
                Call_Webhook( WebHook_Alive )
                log.info("Sleeping for {} seconds".format(Update_Interval))
    # If the environment variable for healthcheck was set, touch the test file
                if Heartbeat_Enabled & os.path.isfile(Config_File_Name):
                    pathlib.Path( Healthcheck_Heartbeat_File_Name ).touch()
                    log.debug("Touching healthcheck file {}".format(Healthcheck_Heartbeat_File_Name))
    # Go to sleep for the duration
                time.sleep(Update_Interval)        

    # Check if the config file has been updated. If it has, re-read it.
            if not os.path.isfile(Config_File_Name):
                log.critical("Configuration file {} no longer not found.".format(Config_File_Name))
            else:
                Config_File_Moddate = os.stat(Config_File_Name)[8]
                Config_File_Current_Timestamp = time.ctime(Config_File_Moddate)

                if Config_File_Previous_Timestamp != Config_File_Current_Timestamp:
                    log.info("Config file {} has been updated, re-reading.".format(Config_File_Name))
                    Read_Configuration()
                    Config_File_Previous_Timestamp = Config_File_Current_Timestamp

    except (KeyboardInterrupt):
        Call_Webhook( WebHook_Alert + "UserTerm" )
        log.warning("User terminated program")
        return

if __name__ == '__main__':
    main()

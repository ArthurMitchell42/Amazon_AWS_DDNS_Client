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
import os

#====================================================================================================
# Global definitions
#====================================================================================================
try:
    File_Paths = os.environ['AWS_CONFIG_PATH']
except KeyError: 
    print("Environment variable 'AWS_CONFIG_PATH' not found.")
    File_Paths = ""

Log_File_Name = File_Paths + "AWS_Route53_DDNS.log"
Config_File_Name = File_Paths + "AWS_Route53_DDNS.ini"
log = logging.getLogger('AWS_Route53_DDNS')

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
            log.warning("Failed to reach AWS IP checking page server. Reason: %s", e.reason)
        elif hasattr(e, 'code'):
            log.warning("The server could't fulfill the request. Error code: %s", e.code)
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
    return

#====================================================================================================
# Main function
#====================================================================================================
def main():
#====================================================================================================
# Set up logging
#====================================================================================================
    log.setLevel(logging.DEBUG)

    #logfile = logging.FileHandler(Log_File_Name)
    logfile = logging.handlers.RotatingFileHandler(Log_File_Name, maxBytes=100000, backupCount=5)
    logfile.setLevel(logging.DEBUG)
    
    logcons = logging.StreamHandler()
    logcons.setLevel(logging.DEBUG)

    logform = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s') #  %(name)s
    logfile.setFormatter(logform)
    logcons.setFormatter(logform)

    log.addHandler(logfile)
    log.addHandler(logcons)
    
    log.info("Program started.")

#====================================================================================================
# Read the configuration file
#====================================================================================================
    config = configparser.ConfigParser()
    config.read(Config_File_Name)

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

    log.debug("Domains and records loaded: {} {}".format(Domain_Names, Record_Names))
    log.debug("Interval loaded: {}".format(Update_Interval))
    log.debug("Exception interval loaded: {}".format(Exception_Interval))
    log.debug("TTL: {}".format(TTL_Interval))

#====================================================================================================
# Try to set up the session object from the credientials file
#====================================================================================================
    try:
        Route53_Session = boto3.Session(profile_name='route53_user')
    except botocore.exceptions.ProfileNotFound :
        log.debug("Profile 'route53_user' not found in credentials file. Trying default credentials.")
        try:
            Route53_Session = boto3.Session(profile_name='default')
        except botocore.exceptions.ProfileNotFound :
            log.debug("Default credential profile not found in credentials file. Falling back to environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.")
            Route53_Session = boto3.Session()
    else:
        log.debug("Profile route53_user found in credentials file.")

# Create the Route53 client object
    Route53_Client = Route53_Session.client( 'route53' )

#====================================================================================================
# Initialise a false last IP address to force an update check
#====================================================================================================
    time.sleep(5)
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
                log.error("Couldn't retrieve the external IP address")
                Issue_Updating = True
            else:
                log.info("External IP address: {}".format(External_Address))
                if External_Address != Last_External_Address: 
                    if Last_External_Address != "0.0.0.0":
                        log.warning("External IP address has changed from {} to {}".format(Last_External_Address, External_Address))
                    Last_External_Address = External_Address
            
    # Loop round the list of domain names and records we are montioring
                for Domain_Index in range(0, len(Domain_Names)):
                    time.sleep(5)
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
                log.warning("Sleeping for {} seconds".format(Exception_Interval))
                time.sleep(Exception_Interval)        
            else:
                log.info("Sleeping for {} seconds".format(Update_Interval))
                time.sleep(Update_Interval)        
    except (KeyboardInterrupt):
        log.warning("User terminated program")
        return

if __name__ == '__main__':
    main()

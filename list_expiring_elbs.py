#
#  Prints out list of elb/alb and the cert/exp date
#

from datetime import datetime
from datetime import timedelta
from datetime import tzinfo
from collections import defaultdict
import boto3

# %!$@! hack? to get tzinfo in utc
# to compare timezone aware times!
ZERO = timedelta(0)
class UTC(tzinfo):
    def utcoffset(self, dt):
      return ZERO
    def tzname(self, dt):
      return "UTC"
    def dst(self, dt):
      return ZERO
UTC = UTC()

# List server certificates through the pagination interface

def get_expiring_certs(botoconn, days):
  utc_date = datetime.now(UTC) + timedelta(days)
  expiringcerts = defaultdict(list)
  paginator = botoconn.get_paginator('list_server_certificates')
  for response in paginator.paginate():
    for certificate in response['ServerCertificateMetadataList']:
      expire_date = certificate['Expiration']
      if utc_date > certificate['Expiration']:
        expiringcerts[certificate['Arn']].append({'Expiration':certificate['Expiration']})
  return expiringcerts

# Get ELBs that have listeners matching expired certs

def get_expiring_elbs(botoconn, certs):
  expiringelbs = defaultdict(list)
  paginator = botoconn.get_paginator('describe_load_balancers')
  for response in paginator.paginate():
    for elb in response['LoadBalancerDescriptions']:
      for listener in elb['ListenerDescriptions']:
        if listener['Listener']['Protocol'] == 'HTTPS':
          sslcertarn = listener['Listener']['SSLCertificateId']
          if sslcertarn == "Invalid-Certificate":
            expiringelbs[elb['DNSName']].append('Invalid-Certificate')
          if sslcertarn in certs:
            expiringelbs[elb['DNSName']].append(sslcertarn)
  return expiringelbs

# Get ALBs that have listeners matching expired certs

def get_expiring_albs(botoconn, certs):
  expiringalbs = defaultdict(list)
  paginator = botoconn.get_paginator('describe_load_balancers')
  for response in paginator.paginate():
    for alb in response['LoadBalancers']:
      for listener in botoconn.describe_listeners(LoadBalancerArn=alb['LoadBalancerArn'])['Listeners']:
        if listener['Protocol'] == 'HTTPS':
          for certificate in listener['Certificates']:
            sslcertarn = certificate['CertificateArn']
            if sslcertarn == "Invalid-Certificate":
              expiringalbs[alb['DNSName']].append('Invalid-Certificate')
            if sslcertarn in certs:
              if not sslcertarn[:11] == "arn:aws:acm":
                expiringalbs[alb['DNSName']].append(sslcertarn)
  return expiringalbs

def print_data(balancers, expiring_certs):
  for balancer in balancers:
    for item in balancers[balancer]:
      if item == "Invalid-Certificate":
        print("%s,%s,%s" % (balancer, item, ""))
      else:
        for expdate in expiring_certs[item]:
          print("%s,%s,%s" % (balancer, item, expdate['Expiration']))


if __name__ == "__main__":

  # Create our global boto3 clients (iam, ec2)
  iam = boto3.client('iam', region_name='us-east-1')
  ec2 = boto3.client('ec2', region_name='us-east-1')

  # IAM Certs are global in the account, 
  expiring_certs = get_expiring_certs(iam, 3650)

  # Loop through each region, getting all ELB
  # and ALB listeners, checking against the
  # expired ssl list generated 
  for RegionList in ec2.describe_regions()['Regions']:
    elbconn = boto3.client('elb', region_name=RegionList['RegionName'])
    albconn = boto3.client('elbv2', region_name=RegionList['RegionName'])
    expiringelbs = get_expiring_elbs(elbconn, expiring_certs)
    expiringalbs = get_expiring_albs(albconn, expiring_certs)
    print_data(expiringelbs, expiring_certs)
    print_data(expiringalbs, expiring_certs)

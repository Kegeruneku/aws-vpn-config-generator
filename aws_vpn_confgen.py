#!/usr/bin/env python3

# Load dependencies

## Buildin
import sys
import re
import argparse

## External
import boto3
import xmltodict
from jinja2 import Template

def get_vpn_configuration(vpn_connection, region='us-east-1', profile='default', name_tag='Name'):
    """This function returns an AWS VPN configuration
    as a Python dict object, extracted from the configuration
    AWS returns as an XML object

    Keyword arguments:
    vpn_connection -- the AWS VPN Connection ID
    region -- optional AWS region
    profile -- optional AWS profile
    name_tag -- optional AWS tag to name the vpn connection
    """

    # Connect to EC2 using boto3
    s = boto3.Session(profile_name=profile, region_name=region)
    ec2 = s.client('ec2')

    # Get the VPN connections matching the search criteria
    vpn = ec2.describe_vpn_connections(VpnConnectionIds=[ vpn_connection ])

    # Get the VPN Gateway ID and extract the associated VPC CIDR block from it
    vgw_id         = vpn['VpnConnections'][0]['VpnGatewayId']
    vgw            = ec2.describe_vpn_gateways(VpnGatewayIds=[ vgw_id ])
    vpc_id         = vgw['VpnGateways'][0]['VpcAttachments'][0]['VpcId']
    vpc            = ec2.describe_vpcs(VpcIds=[ vpc_id] )
    vpc_cidr_block = vpc['Vpcs'][0]['CidrBlock']

    # Extract the VPN configuration
    cgw_configuration = xmltodict.parse(vpn['VpnConnections'][0]['CustomerGatewayConfiguration'])
    vpn_configuration = cgw_configuration['vpn_connection']['ipsec_tunnel']

    # Append our own values to the configuration block
    vpn_configuration[0]['vpc_cidr_block'] = vpc_cidr_block

    vpn_name_extension = 'unknown'

    # If name_tag is defined and found in the VPN connection tags, use it as tunnel name
    for i in vpn['VpnConnections'][0]['Tags']:
        if i['Key'] == name_tag:
            vpn_name_extension = re.sub('[^A-Za-z0-9]+', '-', i['Value'])

    vpn_configuration[0]['name'] = 'aws-%s-%s' % ( region, vpn_name_extension )

    # Return it
    return vpn_configuration

def generate_racoon_configuration(vpn_configuration):
    """Generate a racoon-compatible VPN configuration

    Keyword arguments:
    vpn_configuration -- An AWS VPN connection Python object
    """

    # Load templates
    with open('templates/racoon_conf.jinja2') as f:
        racoon_conf = f.read()
    template_racoon = Template(racoon_conf)

    print(template_racoon.render(
        vpn_configuration = vpn_configuration,
        ike_encryption_protocol = ''.join(vpn_configuration[0]['ike']['encryption_protocol'].split('-')[:2]),
        ike_authentication_protocol = vpn_configuration[0]['ike']['authentication_protocol'],
        ipsec_encryption_protocol = ''.join(vpn_configuration[0]['ipsec']['encryption_protocol'].split('-')[:2]),
        ipsec_authentication_protocol = '_'.join(vpn_configuration[0]['ipsec']['authentication_protocol'].split('-')[:2])
    ))

def generate_strongswan_configuration(vpn_configuration):
    """Generate a strongswan-compatible VPN configuration

    Keyword arguments:
    vpn_configuration -- An AWS VPN connection Python object
    """

    # Load templates
    with open('templates/strongswan_tunnel_conf.jinja2') as f:
        tunnel_conf = f.read()
    template_tunnel = Template(tunnel_conf)

    print(template_tunnel.render(
        vpn_configuration = vpn_configuration,
        ike_encryption_protocol = ''.join(vpn_configuration[0]['ike']['encryption_protocol'].split('-')[:2]),
        ike_authentication_protocol = vpn_configuration[0]['ike']['authentication_protocol'],
        ike_perfect_forward_secrecy = vpn_configuration[0]['ike']['perfect_forward_secrecy'][-1],
        ipsec_perfect_forward_secrecy = vpn_configuration[0]['ipsec']['perfect_forward_secrecy'][-1],
        ipsec_encryption_protocol = ''.join(vpn_configuration[0]['ipsec']['encryption_protocol'].split('-')[:2]),
        ipsec_authentication_protocol = '_'.join(vpn_configuration[0]['ipsec']['authentication_protocol'].split('-')[:2])
    ))

def generate_routebased_strongswan_configuration(vpn_configuration):
    """Generate a strongswan-compatible route-based VPN configuration

    Keyword arguments:
    vpn_configuration -- An AWS VPN connection Python object
    """

    # Load templates
    with open('templates/strongswan_tunnel_conf_routebased.jinja2') as f:
        tunnel_conf = f.read()
    template_tunnel = Template(tunnel_conf)

    print(template_tunnel.render(vpn_configuration = vpn_configuration))

def generate_quagga_configuration(vpn_configuration):
    """Generate a quagga-compatible BGP configuration

    Keyword arguments:
    vpn_configuration -- An AWS VPN connection Python object
    """

    # Load templates
    with open('templates/quagga_conf.jinja2') as f:
        quagga_conf = f.read()
    template_quagga = Template(quagga_conf)

    if 'bgp' in vpn_configuration[0]['vpn_gateway'].keys():
        print(template_quagga.render(vpn_configuration=vpn_configuration))
    else:
        print('\n# No BGP configuration for %s (tunnel may be using static routing)' % vpn_configuration[0]['name'])

def generate_bird_configuration(vpn_configuration):
    """Generate a bird-compatible BGP configuration

    Keyword arguments:
    vpn_configuration -- An AWS VPN connection Python object
    """

    # Load templates
    with open('templates/bird_conf.jinja2') as f:
        bird_conf = f.read()
    template_bird = Template(bird_conf)

    if 'bgp' in vpn_configuration[0]['vpn_gateway'].keys():
        print(template_bird.render(vpn_configuration=vpn_configuration))
    else:
        print('\n# No BGP configuration for %s (tunnel may be using static routing)' % vpn_configuration[0]['name'])

if __name__ == "__main__":

    # Create argument parser and initialize it
    parser = argparse.ArgumentParser(description='Generates a StrongSwan configuration from an AWS VPN gateway ID')

    parser.add_argument('--vpn-connection', required=True, help='AWS VPN Connection ID')
    parser.add_argument('--region', default='us-east-1', help='AWS Region (defaults to \'us-east-1\')')
    parser.add_argument('--profile', default='default', help='AWS Configuration profile (defaults to \'default\')')
    parser.add_argument('--format', default='strongswan-quagga', help='Configuration format to generate (defaults to \'strongswan-quagga\', can be a combination of \'strongswan-\', \'routedstrongswan-\', \'racoon-\' and \'-quagga\', \'-bird\')')
    parser.add_argument('--name-tag', default='Name', help='VPN connection tag to base the VPN name on (defaults to \'Name\')')

    # Set initial values according to arguments
    args           = parser.parse_args()
    profile        = args.profile
    region         = args.region
    vpn_connection = args.vpn_connection
    format         = args.format
    name_tag       = args.name_tag

    # Download VPN configuration from AWS
    vpn_configuration = get_vpn_configuration(vpn_connection, region, profile, name_tag)

    # Generate IPSec configuration (if necessary)
    if re.match(r'^routedstrongswan.*', format):
        generate_routebased_strongswan_configuration(vpn_configuration)
    elif re.match(r'^strongswan.*', format):
        generate_strongswan_configuration(vpn_configuration)
    elif re.match(r'^racc?oon.*', format):
        generate_racoon_configuration(vpn_configuration)
    else:
        print('ERREUR: Le format %s n\'est pas supporté.' % format)
        sys.exit(1)

    # Generate BGP configuration (if necessary... too)
    if re.match(r'.*-quagga$', format):
        generate_quagga_configuration(vpn_configuration)
    elif re.match(r'.*-bird$', format):
        generate_bird_configuration(vpn_configuration)

# AWS VPN Racoon / StrongSwan configuration generator

This script generates IPSec VPN (and optionnally, BGP) configurations,
enabling its user to use AWS VPN connections easily.

It supports StrongSwan (route and policy based) and Raccoon IPSec setups, and
Quagga and BIRD BGP services.

## Prerequisites

This tool is mainly developed on Python3, but _should_ be Python 2.7
compatible.

Please take a look at requirements.txt for the necessary dependencies.

## Utilisation

By default, the generated format is 'strongswan', you may use `--format` to change it.

Example:
```bash
./aws_vpn_confgen.py --profile=infra --region=eu-west-1 --name-tag=project --vpn-connection=vpn-d1234567
```

To get help: `./aws-vpn-confgen.py -h`

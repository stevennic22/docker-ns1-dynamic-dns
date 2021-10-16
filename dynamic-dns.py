#!/usr/bin/env python3
# -*- coding: utf-8 -*-

### Purpose: ##############################################
###  Update public IP for scripts (check hourly maybe?) ###
###  Set Dynamic DNS through NS1                        ###
###  Enables options for Linode public IP check         ###
###########################################################
#To-Do: Handle IPv6 records when there isn't an IPv6 address.
#       Handle no record existing at all for either IPv4 or IPv6 addresses.
#       This _should_ be sufficient for home and IPv4 Linode usage.

import requests, json, os, time, yaml
from pathlib import Path
from random import randint
from ns1 import NS1, Config, rest

def linode_api_check(API_KEY, HOST_KEY):

  headers = {"Authorization": "Bearer {0}".format(API_KEY)}

  storage = requests.get("https://api.linode.com/v4/linode/instances/{0}/ips".format(HOST_KEY), headers=headers)
  log_print("URL being checked against: LinodeAPI")
  return(storage.json()["ipv4"]["public"][0]["address"])
  #ipv6: storage.json()["ipv6"]["slaac"]["address"]

def external_wan():
  import subprocess, re
  resources_to_check_against = ["https://api.ipify.org?format=json", "https://ipinfo.io", "https://ifconfig.co/json", "https://iplist.cc/api/"]

  #if (self.protocol == 6):
  #  url = resources_to_check_against[(3%randint(1,2))] # 0-1
  #else:
  url = resources_to_check_against[(7%randint(1, 6))] # 0-3
  log_print("URL being checked against: {0}".format(url))

  return(requests.get(url, timeout=25).json()["ip"])

def get_ip(host):
  if host["method"] == "LinodeAPI":
    return(linode_api_check(host["API_KEY"], host["HOST_KEY"]))
  elif host["method"] == "external":
    return(external_wan())

def check_ip(my_ip, dns_ip):
  """ Check whether current IP matches IP in DNS
  Arguments:
  record -- the nsone.records.Record object to check
  """

  remote_ip = dns_ip.data['answers'][0]['answer'][0]
  if my_ip == remote_ip:
    log_print("Current IP ({ip}) matches DNS record for {record}"
              .format(record=dns_ip.domain, ip=my_ip))
    return {'matches': True}
  else:
    log_print("Current IP ({my_ip}) does not match DNS record for {record} ({dns_ip})"
              .format(record=dns_ip.domain, my_ip=my_ip, dns_ip=remote_ip))
    return {'matches': False, 'my_ip': my_ip}

def set_ip(record, new_ip):
  """Set record IP address to new_ip"""
  record.update(answers=[str(new_ip)])
  log_print("Allocated new IP {ip} to {record}"
            .format(record=record.domain, ip=new_ip))

def create_record(zone, subdomain, new_ip, allowed_countries):
  """Set record IP address to new_ip"""
  zone.add_A(
    subdomain,
    [
      {"answer": [new_ip], "meta": {"up": True, "country": allowed_countries}},
    ]
  )

  log_print("Created new record ({record}) with IP: {ip}"
            .format(record=subdomain, ip=new_ip))

def log_print(log_string):
  print(time.strftime("%c") + " ::: " + str(log_string))

def main():
  if os.path.isfile('/app/config/config.yml') is not True:
    print('/app/config/config.yml does not exist or is not a file, exiting.')
    exit(1)

  config_file = yaml.safe_load(open('/app/config/config.yml', 'r'))

  for domain in config_file:
    nsone_config = Config()
    nsone_config.createFromAPIKey(config_file[domain]['api-key'])
    nsone_config["transport"] = "requests"
    client = NS1(config=nsone_config)
    zone = client.loadZone(domain)

    for host in config_file[domain]['hosts']:
      log_print("Checking subdomains for host: {}".format(host["name"]))
      my_ip = get_ip(host)
      for x in host["subdomains"]:
        try:
          if x == "@":
            host["record"] = zone.loadRecord(domain, 'A')
          else:
            host["record"] = zone.loadRecord(x, 'A')
          result = check_ip(my_ip, host["record"])
          if result['matches'] is False:
            if not config_file[domain]["test"]:
              set_ip(host["record"], result['my_ip'])
        except rest.errors.ResourceException:
          full_domain = domain
          if x != "@":
            full_domain = "{0}.{1}".format(x, domain)

          if not config_file[domain]["test"]:
            if "allowed_countries" not in config_file[domain]:
              config_file[domain]["allowed_countries"] = ['US', 'CA']
            create_record(zone, full_domain, my_ip, config_file[domain]["allowed_countries"])

if __name__ == "__main__":
  main()

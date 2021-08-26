#!/usr/bin/env python3

import json
import os

configdir = '/data/app/config/tunnel/'

if not os.path.exists(configdir + 'config.json'):
    config = {'self': {}, 'peers': []}
    print("config.json does not exist, creating it.")
    os.makedirs(configdir, exist_ok=True)
else:
    try:
        with open(configdir + 'config.json', 'r') as f:
            config = json.loads(f.read())
    except Exception as e:
        print("Could not parse config file: {}", e)
        exit(1)

if 'self' in config and config['self']:
    print("Self is already configured:")
    print(json.dumps(config['self'], indent=2))
    a = input("Change y/N? ")
    if a != "y" :
        exit(0)

identity = input("Self identity: ")
keyfile = input("Private key file: ")
passphrase = input("Private key passphrase: ")

config['self']['identity'] = identity
config['self']['keyfile'] = keyfile
config['self']['passphrase'] = passphrase

try:
    with open(configdir + 'config.json', 'w') as f:
        f.write(json.dumps(config, indent=2))
except:
    print("Could not write config file.")
    exit(1)

print("Succesfully modified config.")

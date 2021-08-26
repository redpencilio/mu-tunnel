#!/usr/bin/env python3

import json
import os

def findidentity(peers, identity):
    for i, peer in enumerate(peers):
        if peer['identity'] == identity:
            return i
    return -1

def identities(peers):
    identities = []
    for peer in peers:
        identities.append(peer['identity'])
    return identities

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

if not 'peers' in config:
    config['peers'] = []

ids = identities(config['peers'])
print("Current peers: " + ", ".join(ids))

choice = input("Add a new peer (a), change an existing peer (c), or remove a peer (r)? ")
if choice == 'a':
    identity = input ("New peer identity: ")
    keyfile = input("New peer public key file: ")
    address = input("New peer remote address (optional): ")
    allowed = input("New peer allowed prefixes (optional, comma-separated): ")
    newpeer = {"identity": identity, "file": keyfile}
    if address != "":
        newpeer['address'] = address
    if allowed != "":
        newpeer['allowed'] = [x.strip() for x in allowed.split(',')]
    config['peers'].append(newpeer)

elif choice == 'c':
    identity = input("Enter the identity of the peer to change: ")
    index = findidentity(config['peers'], identity)
    if index == -1:
        print("Unknown peer")
        exit(2)

    print("Current config for " + identity + ": ")
    print(json.dumps(config['peers'][index], indent=2))

    identity = input ("New identity (empty to keep current): ")
    keyfile = input("New public key file (empty to keep current): ")
    address = input("New remote address (empty to keep current, 'r' to remove): ")
    allowed = input("New allowed prefixes (empty to keep current, 'r' to remove, comma-separated): ")
    if identity != "":
        config['peers'][index]['identity'] = identity
    if keyfile != "":
        config['peers'][index]['keyfile'] = keyfile
    if address != "":
        if address == "r":
            del config['peers'][index]['address']
        else:
            config['peers'][index]['address'] = address
    if allowed != "":
        if allowed == "r":
            del config['peers'][index]['allowed']
        else:
            config['peers'][index]['allowed'] = [x.strip() for x in allowed.split(',')]

elif choice == 'r':
    identity = input("Enter the identity of the peer to remove: ")
    index = findidentity(config['peers'], identity)
    if index == -1:
        print("Unknown peer")
        exit(2)

    config['peers'].pop(index)

else:
    print("Invalid choice.")
    exit(2)

try:
    with open(configdir + 'config.json', 'w') as f:
        f.write(json.dumps(config, indent=2))
except:
    print("Could not write config file.")
    exit(1)

print("Succesfully modified config.")

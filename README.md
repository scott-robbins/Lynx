# LYNX 
A simple peer to peer file sharing and messaging application.

## Installation (Linux Only)
Download the source with git using:
```
git clone https://github.com/scott-robbins/Lynx
cd Lynx/code_py2.7/
python client.py
```

## Design
Running the client will generate some files locally, including a private key
which will be used (along with a public key derived from private key) to encrypt
data, files, messages, etc. This means every client, or *peer*, has a unique 
key to use for signing and encrypting messages. 

Communication between clients is done by first synchronizing and negotiating the
session through a rendezvous server, and then continued point to point.
Once you've registered with a rendevouz server, the client will present a message 
for visiting one of a few domains (generated for free with dynamic dns services and hosted by
primary nodes in a Lynx network which are configured to face the public internet/WAN).

## Features (Under Development)
* File Sharing 

* Messaging 

__________________________________________________________________________________

This project is currently under development     **Last Updated January 2020**
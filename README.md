# LYNX 
A simple peer to peer file sharing and messaging application.

## Installation (Linux Only)
Download the source with git using:
`git clone https://github.com/scott-robbins/Lynx; 
cd Lynx;
python client.py`

## Design
Running the client will generate some files locally, including a private key
which will be used (along with a public key derived from private key) to encrypt
data, files, messages, etc. This means every client, or *peer*, has a unique 
key to use for signing and encrypting messages. 

Communication between clients is done by first synchronizing and negotiating the
session through a rendezvous server, and then continued point to point.  

## Features
* File Sharing 

* Messaging 

__________________________________________________________________________________

This project is currently under development     **Last Updated January 2020**
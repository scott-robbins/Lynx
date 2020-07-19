# LYNX 
A simple peer to peer file sharing and messaging application.

## Installation (Linux Only)
Download the source with git using:
```
git clone https://github.com/scott-robbins/Lynx
cd Lynx/code/0.05
```
Get started with:
```
python client.py -headless
sudo python selfserve.py
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

* Media Sharing (Live Camera Feeds, Audio Streaming)

![dash](https://raw.githubusercontent.com/scott-robbins/Lynx/origin/dash.png)


## Scaling 
The Next step I need to figure out, will be creating a method for cloning/adding public nodes which will
benefit the entire network in several ways, and also sort of unlock some of the kind of emergent properties 
you get from peer to peer networks. Let me elaborate. 

As of now the burden of file upload/download is constrained by the single central server that must track and 
synchronize the initial authentication of a client, and *all uploads/downloads* . This will not scale well if
the number of clients increases. 

On the other hand, with say half a dozen public nodes (each with a unique public domain) a very different 
architecture could be implemented. In this case, whenever a file is uploaded to one public node, it's name and
a uniquely identifying hash of it would be added to a list containing all the shared files present among all of
the  public nodes. If each node then sends each other nodes it's own update, listing of all file hashes it has,
the nodes will collectively generate/maintain a list of the resources each other has (and a master list of the
entire set of files available). 

Now when users want to download/upload a file, the will visit perhaps one master site which will redirect them to
the geographically closest node, which will be able to serve them any file on the network (even if it doesn't have it,
it will know which other node does because of this distributed hashing system).  


__________________________________________________________________________________

This project is currently under development     **Last Updated February 2020**

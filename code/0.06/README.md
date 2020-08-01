# LYNX v0.06
This is the latest version of my attempt at creating a full stack peer-to-peer python 
application. I want to make something that I can fully understand without relying too
heavily on large libraries.

## Changes from 0.04 
The last version I updated user interface/experience to instead created by running a 
local flask instance and rendering everything in the browser. 

## Changes from 0.05 
Now I need to introduce crypto to secure the communication between peers and with the 
rendevous server. Doing this correctly is challenging but interesting so far. I will 
detail below the scheme I am trying to use. 

## Security 
While much of this is somewhat "do-it-yourself", cryptography is not something that
you should try to re-invent... or at least that is a *very* different project. I am
opting to use basic python crypto libraries for this stuff for that reason. These 
and Flask are really the only dependencies for the project (well, and it's written
for Linux). 

When you create an account, your machine will create an RSA public/private key pair,
and then reach out to the central server to check in. The initial check in is important because it initializes the cryptographic overhead for further encounters per client. 

* The server must only keep track of one Public Key for every client.
* Every client is given the public key of the central server when they check in. 
* All clients initially discuss a session key using public key encryption, and 
  continue using AES encrypted with this session key (much faster than AES). 


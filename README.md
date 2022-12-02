# WhatsApp

 A python script representing WhatsApp end-to-end encryption system based on the WhatsApp
whitepaper from December 19,2017.

## Terms

### Public Key Types 
On installation time for each user Public Key Types are created:
* Identity Key Pair, curve25519 key pair
* Signed Pre Key, Curve25519 key pair signed by the Identity Key
* One-Time Pre Keys, key pairs for one time use

### Session Key types
* Root Key – A 32-byte value that is used to create Chain Keys.
* Chain Key – A 32-byte value that is used to create Message 
Keys.
* Message Key – An 80-byte value that is used to encrypt message 
contents.

## Client Registration and Session Setup

On registering the WhatsApp client transmits the public Identity Key, the public Signed Pre Key (with its signature) and a batch of One-Time Pre Keys to the server.

To initiate a session the WhatsApp client has to establish and encrypted session and has to:
* Request the public Identity Key, public Signed Pre Key and a public One-Time Pre Key for the recipient
* The initiator saves the Public Key Types (Identity Key as I_recipient,Signed Pre Key as S_recipient,One-Time Pre Key as O_recipient) of the recipient and generates an ephemeral key pair ( E_initiator)
* Initiator loads own Identity Key (I_initiator) and calculates a master secret
```
master_secret = 
ECDH(Iinitiator, Srecipient) || ECDH(Einitiator, Irecipient) || 
ECDH(Einitiator, Srecipient) || ECDH(Einitiator, Orecipient)
```
* Initiator uses HKDF to create Root Key(32-byte value to create Chain Keys) ,Chain Keys(32-byte value that is used to create Message keys) from the master_secret

The initiator includes the information in the header of the messages sent) so that recipient builds a corresponding session (E_initiator, I_initiator)

For session setup the recipient:
1. Calculates the master_secret using its on private keys and the public keys in the header of the incoming message
2. Deletes the One-Time Pre Key 
3. The Initiator uses HKDF to derive Root Key and Chain Keys from master_secret





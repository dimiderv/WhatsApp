# WhatsApp

 A python script representing WhatsApp end-to-end encryption system based on the WhatsApp
whitepaper from December 19,2017.

On installation time for each user Public Key Types are created:
*Identity Key Pair, curve25519 key pair
*Signed Pre Key, Curve25519 key pair signed by the Identity Key
*One-Time Pre Keys

On registering the WhatsApp client transmits the public Identity Key, the public Signed Pre Key (with its signature) and a batch of One-Time Pre Keys to the server.

To initiate a session the WhatsApp client has to establish and encrypted session and has to:
*Request the public Identity Key, public Signed Pre Key and a public One-Time Pre Key for the recipient
*The initiator saves the Public Key Types (Identity Key as I_recipient,Signed Pre Key as S_recipient,One-Time Pre Key as O_recipient) of the recipient and generates an ephemeral key pair ( E_initiator)
*Initiator loads own Identity Key (I_initiator) and calculates a master secret

```
master_secret = 
ECDH(Iinitiator, Srecipient) || ECDH(Einitiator, Irecipient) || 
ECDH(Einitiator, Srecipient) || ECDH(Einitiator, Orecipient)
```

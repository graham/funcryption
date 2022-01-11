API Authentication and Authorization
====================================

There are a number of ways to authenticate between API Services, this is an attempt to create one that provides some features without being overly complex. It is easy to implement, and reason about.

Sending the same API key with every request is reasonable when you have 1 server or database. The server looks up that key, determines authentication (who are you) and authorization (what can you do) and moves on. However, there are two problems with this setup at scale:

 1. Sending the same API key every request means that API key can show up in error logs or debug information, this leaks the credentials.
 2. If there are multiple services, they all now have a single point for determining what an API key can do.
 
There are a number of ideas for solving this, the first, is using a simple level of encryption that allows the client to send different data with every request that is still validatable by the server. Like a 2FA code, the API key is easy enough to generate that the client can easily roll their API key forward as often as they want.

To solve #2, one option is to encode what the key can do INSIDE the key itself. JWT, a similar authentication system, allows for this.

JWT doesn't solve #1, and it doesn't appear to be well regarded in the industry. I can't tell if JWT is something propped up by Auth0 or unpopular becaues it appears that it's easy to misconfigure.


This solution
=============

This solution is similar (conceptually) to how something like OAuth (eventually) works, however, we get to skip the negotiation and handshake phase because we own all the endpoints. There is some shared private data, that allows clients and servers to communicate securely. We are able to give keys finite lifetimes, both from the client (expire in 5 minutes) and from the server (expire in 3 months).

Practically, it can be a little confusing, but once you understand it, it's mostly simple.

1. The client has two pieces of data, first, a encryption key. It uses this to generate API keys that can be decrypted by the server. It also has some "Magic" data, this data can't be read or modified by the client. In order to generate an API key, it encrypts the magic data with the encryption key and sends it to the server along with any other data it has.

As a result, the client can choose to generate the key once per day, or once per minute, or even once per request depending on the agreement between the client/server.

2. The server has two pieces of data, a outer_key and an inner key. The outer key is the same as the encryption key that the client is using, the inner key is not shared, but is used to encrypt authorization data, that encrypted authorization data IS the magic data that the client has.

This outer/inner pair is created by a central authority and can be regenerated easily at any time.

As a result, clients/servers can authenticate and authorize without talking to the central authority on every request.


DOs and DONTs
=============

Lets be upfront about what we do care about and what we don't care about.

- We DO want a way to properly authenticate (who are you) and authorize (what can you do) across services. In most cases this occurs within the confines of a production network.
- We DO want tokens to expire, so that over time, valid keys are not found in log files. This also helps prevent replay attacks.
- We DO want services accepting tokens to not have to check with a central authority on every call, the token itself should be secure enough that the server can trust it for authorization information. The client shouldn't be able to tamper with this.

Beyond that I'm adding a constraint of my own.

- We DO want tokens to be non-deterministic and easily generated, primarily so that no single key is used for long periods of time.

Having expiration without non-deterministic generation means we likely need VERY long expiration times (months) in order to be ergonomic.

- We DO want the ability to ROTATE tokens without too much difficulty or performance loss. This allows us to sunset customers that fail to update gracefully.

Some of the things we DONT care about.

- We DONT want to encrypt our data payloads between systems with THIS system. If encryption in flight is needed, this system shouldn't be the one to do it.
# funcryption

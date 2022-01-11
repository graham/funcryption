import json

from cryptography.fernet import Fernet

# This should not be used to manage webbrowser sessions.
# The goal here is that within a service architecture
# different systems can have access to each other with
# two main priorities.
#
# 1. No auth service is needed to determine access
#    at the time of request. Authorization information
#    is stored in the token.
# 2. The keys themselves are non-deterministic and thus
#    cannot be replayed easily. Fernet allows this easily
#    since timestamp is encoded and encryption of the same
#    data results in different payloads.
#
# The burden here is that there is a `magic` data that
# the client can't see inside, and must encrypt with a shared
# key and send to the server.
#
# The server has two keys, the public key, and a private key
# that it uses to decrypt the inner magic. Not to be mistaken
# with ACTUAL OpenSSL pub/priv keys. Hence the naming of
# outer and inner keys.
#
# The issue with keys that don't change is that they are often
# found in logging data, which allows for replay attacks.
# In a world where ident isn't verified by a central authority
# at request time (requirement #1) this becomes a greater risk.
# Hence the solution. Theoretically complicated, but actually
# pretty simple.
#
# Fernet provides nice support for key rotation, is architecturally
# quite simple, and performant enough for this use case.


class Service:
    def __init__(self, inner_secret, outer_secret):
        self.inner_secret = inner_secret
        self.outer_secret = outer_secret

    def gen_magic(self, claims, for_service):
        f = Fernet(self.inner_secret)
        return f.encrypt(json.dumps({
            "claims": claims,
            "service": for_service,
        }).encode('ascii'))

    def decode_payload(self, token):
        outer_fernet = Fernet(self.outer_secret)
        encrypted_magic = outer_fernet.decrypt(token)

        inner_fernet = Fernet(self.inner_secret)
        payload = inner_fernet.decrypt(encrypted_magic)

        return json.loads(payload)
        

class Client:
    def __init__(self, key, magic):
        self.key = key
        self.magic = magic

    def gen_api_token(self):
        f = Fernet(self.key)
        return f.encrypt(magic)

if __name__ == '__main__':
    inner_secret, outer_secret = Fernet.generate_key(), Fernet.generate_key()
    serv = Service(inner_secret, outer_secret)
    magic = serv.gen_magic(['read', 'write'], 'graham')

    client = Client(outer_secret, magic)

    tok = client.gen_api_token()

    print(serv.decode_payload(tok))

    

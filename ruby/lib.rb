require 'json'
require 'fernet'

Fernet::Configuration.run do |config|
  config.enforce_ttl = false
  config.ttl         = 60
end

class Service
  def initialize(inner_secret, outer_secret)
    @inner_secret = inner_secret
    @outer_secret = outer_secret
  end

  def magic(claims, for_service)
    payload = { "claims" => claims, "service" => for_service }.to_json
    Fernet.generate(@inner_secret, payload)
  end

  def decode_payload(token)
    encrypted_magic = Fernet.verifier(@outer_secret, token)
    if encrypted_magic.valid?
      payload = Fernet.verifier(@inner_secret, encrypted_magic.message)
      if payload.valid?
        return payload.message
      end
    end
    nil
  end
end

class Client
  def initialize(secret, magic)
    @secret = secret
    @magic = magic
  end

  def gen_api_token
    Fernet.generate(@secret, @magic)
  end
end


def main
  inner_secret = '12345678123456781234567812345678'
  outer_secret = '87654321876543218765432187654321'

  serv = Service.new(inner_secret, outer_secret)

  client = Client.new(outer_secret, serv.magic(['read','write'], 'graham'))

  tok = client.gen_api_token

  puts serv.decode_payload(tok)
end

main()

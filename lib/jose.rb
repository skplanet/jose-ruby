require 'jose/version'
require 'jose/jwe/jwe'
require 'jose/jws/jws'

module SyrupPay
  module JWE
    def compactSeriaization(key, header = {}, payload)
      jwe = SyrupPay::JweSerializer.new(key)
      jwe.compactSerialize(header, payload)
    end

    def compactDeserialization(key, seriaization_input)
      jwe = SyrupPay::JweSerializer.new(key)
      jwe.compactDeserialize(seriaization_input)
    end
  end

  module JWS
    def compactSeriaization(key, header = {}, claims)
      jws = SyrupPay::Jws.new(key)
      jws.compactSerialize(header, claims)
    end

    def compactDeserialization(key, jws_value)
      jws = SyrupPay::Jws.new(key)
      jws.compactDeserialize jws_value
    end
  end
end

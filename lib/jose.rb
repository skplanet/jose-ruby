require 'jose/version'
require 'jose/jwe/jwe'

module SyrupPay
  module JWE
    module_function

    def compactSeriaization(header = {}, key, payload)
      jwe = SyrupPay::JweSerializer.new(key)
      jwe.compactSerialize(header, payload)
    end

    def compactDeserialization(key, seriaization_input)
      jwe = SyrupPay::JweSerializer.new(key)
      jwe.compactDeserialize(seriaization_input)
    end
  end

  module JWS
    module_function

    def compactSeriaization()
    end

    def compactDeserialization()
    end
  end
end




enc = SyrupPay::JWE.compactSeriaization({'alg':'A128KW', 'enc': 'A128CBC-HS256'}, '1234567890123456', 'hahaha')
p enc

src = SyrupPay::JWE.compactDeserialization('1234567890123456', enc)
p src

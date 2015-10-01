require 'jose/version'
require 'jose/jwe/jwe'

module SyrupPay
  module JWE
    module_function

    def compactSeriaization(header = {}, key, payload)
      jwe = SyrupPay::JweSerializer.new(header, key)
      jwe.compactSerialize(payload)
    end

    def compactDeserialization(src, key)
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

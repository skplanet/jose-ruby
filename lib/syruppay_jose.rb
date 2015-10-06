require 'jose/version'
require 'jose/jwe/jwe'
require 'jose/jws/jws'

module SyrupPay
  module JWE
    def compact_serialization_for_test(key, cek, iv, header = {}, payload)
      jwe_serializer = SyrupPay::JweSerializer.new(key)
      jwe_serializer.cek = cek
      jwe_serializer.iv = iv
      jwe_serializer.compactSerialize(header, payload)
    end

    def compact_serialization(key, header = {}, payload)
      jwe_serializer = SyrupPay::JweSerializer.new(key)
      jwe_serializer.compactSerialize(header, payload)
    end

    def compact_deserialization(key, serialization_input)
      jwe_serializer = SyrupPay::JweSerializer.new(key)
      jwe_serializer.compactDeserialize serialization_input
    end
  end

  module JWS
    def compact_serialization(key, header = {}, claims)
      jws_serializer = SyrupPay::JwsSerializer.new(key)
      jws_serializer.compactSerialize(header, claims)
    end

    def compact_deserialization(key, serialization_input)
      jws_serializer = SyrupPay::JwsSerializer.new(key)
      jws_serializer.compactDeserialize serialization_input
    end
  end
end

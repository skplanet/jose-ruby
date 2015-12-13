require 'jose/version'
require 'jose/jwe/jwe'
require 'jose/jws/jws'
require 'active_support/all'

module SyrupPay
  class JsonSignatureCompactSerialization
    def self.serialization(key, header = {}, claims)
      jws_serializer = SyrupPay::JwsSerializer.new(key)
      jws_serializer.compactSerialize(header, claims)
    end
  end

  class JsonEncryptionCompactSerialization
    def self.serialization(key, header = {}, payload)
      payload = payload

      jwe_serializer = SyrupPay::JweSerializer.new(key)
      jwe_serializer.compactSerialize(header, payload)
    end
  end

  class CompactDeserialization
    class UnSupportAlgorithmError < StandardError; end

    def self.deserialization(key, serialized_src)
      header_json = UrlSafeBase64.decode64(serialized_src.split('.').first)

      header = json_to_hash(header_json)

      if (jwe_algorithm?(header[:alg].try(:to_sym)))
        jwe_serializer = SyrupPay::JweSerializer.new(key)
        jwe_serializer.compactDeserialize serialized_src
      elsif (jws_algorithm?(header[:alg].try(:to_sym)))
        jws_serializer = SyrupPay::JwsSerializer.new(key)
        jws_serializer.compactDeserialize serialized_src
      else
        raise UnSupportAlgorithmError, (header[:alg].presence||'alg(nil)')+' is not supported'
      end
    end

    private
    def self.jwe_algorithm?(alg)
      SyrupPay::JweSupportAlgorithm::ALG.include? alg
    end

    def self.jws_algorithm?(alg)
      SyrupPay::JwsSupportAlgorithm::ALG.include? alg
    end

    def self.json_to_hash(json)
      ActiveSupport::JSON.decode(json).with_indifferent_access
    end
  end
end

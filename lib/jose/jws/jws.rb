require 'jose/jwa/alg/hmac_sha256_signature'
require 'active_support/all'

module SyrupPay
  module JwsSupportAlgorithm
    ALG = [:HS256]

    def alg?(alg)
      ALG.include? alg
    end

    def signature_algorithm?(alg)
      case alg
        when :HS256 then SyrupPay::Jwa::HmacSha256Signature.new
        else nil
      end
    end

    def json_to_hash(json)
      ActiveSupport::JSON.decode(json).with_indifferent_access
    end
  end

  class JwsSerializer
    class UnSupportHeaderError < StandardError; end
    class InvalidJwsFormatError < StandardError; end

    include SyrupPay::JwsSupportAlgorithm

    attr_accessor :header
    attr_reader :key, :claims

    def initialize(key)
      @key = key
    end

    def compactSerialize(header = {}, claims)
      @claims = claims
      @header = header.with_indifferent_access

      validate_header!

      jws_alg = signature_algorithm? @header[:alg].try(:to_sym)
      sign_value = jws_alg.sign(@key, hmac_data)

      [@header.to_json, claims, sign_value].collect { |parts| UrlSafeBase64.encode64(parts)}.join('.')
    end

    def compactDeserialize(serialized_input)
      validate_deserialize! serialized_input

      header_json, @claims, sign_value = split_deserialize serialized_input
      @header = json_to_hash(header_json)

      jws_alg = signature_algorithm? @header[:alg].try(:to_sym)
      jws_alg.verify!(@key, hmac_data, UrlSafeBase64.encode64(sign_value))

      @claims
    end

    private
    def validate_header!
      raise UnSupportHeaderError, (header[:alg].presence||'alg(nil)')+' is not supported' unless alg?(header[:alg].try(:to_sym))
    end

    def validate_deserialize!(src)
      raise InvalidJwsFormatError, 'JWS format must be 3 parts' unless src.count('.') == 2
    end

    def split_deserialize(src)
      src.split('.').collect do |parts|
        UrlSafeBase64.decode64(parts)
      end
    end

    def hmac_data
      [@header.to_json, @claims].collect { |parts| UrlSafeBase64.encode64(parts)}.join('.')
    end
  end
end

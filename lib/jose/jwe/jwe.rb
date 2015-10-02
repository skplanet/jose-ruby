require 'active_support/all'
require 'jose/jwa/alg/aes_key_wrap'
require 'jose/jwa/enc/aes128_hmac2565_encryption'
require 'url_safe_base64'

module SyrupPay
  module JweSupportAlgorithm
    ALG = [:A128KW, :A256KW]
    ENC = [:'A128CBC-HS256']

    def alg?(alg)
      ALG.include? alg
    end

    def enc?(enc)
      ENC.include? enc
    end

    def keywrap_algorithm?(alg)
      case alg
        when :A128KW then SyrupPay::Jwa::A128Kw.new
        when :A256KW then SyrupPay::Jwa::A256Kw.new
        else nil
        end
    end

    def encryption_algorithm?(enc)
      case enc
        when :'A128CBC-HS256' then SyrupPay::Jwa::A128CbcHmac256Encryption.new
        else nil
      end
    end

    def json_to_hash(json)
      ActiveSupport::JSON.decode(json).with_indifferent_access
    end
  end

  class JweSerializer
    class UnSupportHeaderError < StandardError; end
    class InvalidJweFormatError < StandardError; end

    include SyrupPay::JweSupportAlgorithm
    attr_accessor :header
    attr_reader :key, :payload
    attr_writer :cek, :iv

    def initialize(key)
      @key = key
    end

    def compactSerialize(header = {}, payload)
      @payload = payload
      @header = header.with_indifferent_access

      validate_header!

      jwe_alg = keywrap_algorithm? @header[:alg].try(:to_sym)
      jwe_enc = encryption_algorithm? @header[:enc].try(:to_sym)

      cek_generator = jwe_enc.content_encryption_generator
      @cek, wrapped_key = jwe_alg.encryption(@key, cek_generator)

      aad = additional_authenticated_data
      cipher_text, at, @iv = jwe_enc.encrypt_and_sign(@cek, @iv, @payload, aad)

      [@header.to_json, wrapped_key, @iv, cipher_text, at].collect do |parts|
        UrlSafeBase64.encode64(parts)
      end.join('.')
    end

    def compactDeserialize(serialized_input)
      validate_deserialize! serialized_input
      header_json, wrapped_key, @iv, cipher_text, at = split_deserialize serialized_input
      @header = json_to_hash(header_json)

      jwe_alg = keywrap_algorithm? @header[:alg].try(:to_sym)
      jwe_enc = encryption_algorithm? @header[:enc].try(:to_sym)

      @cek = jwe_alg.decryption(@key, wrapped_key)

      aad = additional_authenticated_data
      jwe_enc.verify_and_decrypt(@cek, @iv, cipher_text, aad, UrlSafeBase64.encode64(at))
    end

    private

    def additional_authenticated_data
      UrlSafeBase64.encode64 header.to_json
    end

    def validate_header!
      raise UnSupportHeaderError, (header[:alg].presence||'alg(nil)')+' is not supported' unless alg?(header[:alg].try(:to_sym))
      raise UnSupportHeaderError, (header[:enc].presence||'enc(nil)')+' is not supported' unless enc?(header[:enc].try(:to_sym))
    end

    def validate_deserialize!(src)
      raise InvalidJweFormatError, 'JWE format must be 5 parts' unless src.count('.') == 4
    end

    def split_deserialize(src)
      src.split('.').collect do |parts|
        UrlSafeBase64.decode64(parts)
      end
    end
  end
end

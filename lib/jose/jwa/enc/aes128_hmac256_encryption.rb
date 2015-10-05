require 'jose/jwa/enc/content_encryption'
require 'openssl'
require 'bindata'
require 'active_support/security_utils'
require 'url_safe_base64'

module SyrupPay
  module Jwa
    class A128CbcHmac256Encryption < ContentEncryption
      class InvalidVerifyError < StandardError; end

      include ActiveSupport::SecurityUtils

      def initialize
        super 32, 16
      end

      def encrypt_and_sign(cek, iv, payload, aad)
        iv = !iv.nil? ? iv : generate_random_iv
        hmac_key, enc_key = split_key(cek)

        cipher_text = encryption(enc_key, iv, payload)
        at = sign(hmac_key, iv, cipher_text, aad)

        [cipher_text, at, iv]
      end

      def verify_and_decrypt(cek, iv, cipher_text, aad, expected)
        hmac_key, enc_key = split_key(cek)

        verify_authentication_tag!(hmac_key, iv, cipher_text, aad, expected)
        decryption(enc_key, iv, cipher_text)
      end

      private
      def encryption(key, iv, payload)
        cipher = OpenSSL::Cipher.new('AES-128-CBC')
        cipher.encrypt
        cipher.key = key
        cipher.iv = iv
        cipher.update(payload)+cipher.final
      end

      def decryption(key, iv, cipher_text)
        cipher = OpenSSL::Cipher.new('AES-128-CBC')
        cipher.decrypt
        cipher.key = key
        cipher.iv = iv
        cipher.update(cipher_text)+cipher.final
      end

      def sign(key, iv, cipher_text, aad)
        hmac_data = [aad, iv, cipher_text, BinData::Uint64be.new((aad.length*8)).to_binary_s].join
        OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, hmac_data)[0, 16]
      end

      def verify_authentication_tag!(key, iv, cipher_text, aad, expected)
        actual = UrlSafeBase64.encode64(sign(key, iv, cipher_text, aad))
        raise InvalidVerifyError, "expected : #{expected}, actual : #{actual}" unless secure_compare(actual, expected)
      end

      def split_key(cek)
        [cek[0, 16], cek[16, 16]]
      end
    end
  end
end

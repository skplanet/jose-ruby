require 'active_support/security_utils'
require 'openssl'
require 'url_safe_base64'

module SyrupPay
  module Jwa
    class HmacSha256Signature
      class InvalidKeyLengthError < StandardError; end
      class InvalidVerifyError < StandardError; end
      include ActiveSupport::SecurityUtils

      def initialize
        @length = 32
      end

      def sign(key, hmac_data)
        # valid_key_length!(key, @length)

        OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, hmac_data)
      end

      def verify!(key, hmac_data, expected)
        actual = UrlSafeBase64.encode64(sign(key, hmac_data))
        raise InvalidVerifyError, "expected : #{expected}, actual : #{actual}" unless secure_compare(actual, expected)
      end

      private

      def valid_key_length!(key, length)
        actual_key_len = key.blank? ? 0 : key.try(:bytesize)
        expected_key_len = length
        if expected_key_len != actual_key_len
          raise InvalidKeyLengthError, "JWS key must be #{expected_key_len} bytes. Yours key #{actual_key_len} bytes."
        end
      end
    end
  end
end

require 'active_support/security_utils'
require 'openssl'
require 'url_safe_base64'

module SyrupPay
  module Jwa
    class HmacSha256Signature
      class InvalidVerifyError < StandardError; end
      include ActiveSupport::SecurityUtils

      def sign(key, hmac_data)
        OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, hmac_data)
      end

      def verify!(key, hmac_data, expected)
        actual = UrlSafeBase64.encode64(sign(key, hmac_data))
        raise InvalidVerifyError, "expected : #{expected}, actual : #{actual}" unless secure_compare(actual, expected)
      end
    end
  end
end

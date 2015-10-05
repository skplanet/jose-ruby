require 'aes_key_wrap'
require 'active_support/all'
require 'jose/jwa/enc/content_encryptionkey_generator'

module SyrupPay
  module Jwa
    class AesKeyWrap
      class InvalidKeyLengthError < StandardError; end

      def initialize(length)
        @length = length
      end

      def encryption(key, cek)
        valid_key_length!(key, @length)

        if cek.instance_of? SyrupPay::Jwa::ContentEncryptionKeyGenerator
          kek = cek.generate_random_key
        elsif cek.is_a? String
          kek = cek
        elsif cek.is_a? Array
          kek = cek.pack('C*')
        end

        key_binary = str_to_binary(key)
        cek_binary = str_to_binary(kek)

        wrapped_key = AESKeyWrap.wrap(cek_binary, key_binary)
        [kek, wrapped_key]
      end

      def decryption(key, wrapped_cek)
        key_binary = str_to_binary(key)
        AESKeyWrap.unwrap(wrapped_cek, key_binary)
      end

      private
      def str_to_binary(str)
        str.unpack('H*').pack('H*')
      end

      def valid_key_length!(key, length)
        actual_key_len = key.blank? ? 0 : key.try(:bytesize)
        expected_key_len = length
        if expected_key_len != actual_key_len
          raise InvalidKeyLengthError, "JWE key must be #{expected_key_len} bytes. Yours key #{actual_key_len} bytes."
        end
      end
    end

    class A128Kw < Jwa::AesKeyWrap
      def initialize
        super 16
      end
    end

    class A256Kw < Jwa::AesKeyWrap
      def initialize
        super 32
      end
    end
  end
end

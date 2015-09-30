require 'aes_key_wrap'
require 'base64'

module SyrupPay
  module Jwa
    class InvalidKeyLengthError < StandardError; end
    class AesKeyWrap
      def initialize(size)
        @size = size
      end

      def encryption(key, cek)
        valid_key_length!(key, @size)
        key_binary = str_to_binary(key)
        cek_binary = str_to_binary(cek)
        AESKeyWrap.wrap(cek_binary, key_binary)
      end

      def decryption(key, wrapCek)
        key_binary = str_to_binary(key)
        AESKeyWrap.unwrap(wrapCek, key_binary)
      end

      private
      def str_to_binary(str)
        str.unpack('H*').pack('H*')
      end

      def valid_key_length!(key, size)
        fail(InvalidKeyLengthError, 'JWE key must be '+size.to_s+' bytes. Yours key '+key.bytesize.to_s+' bytes.') if size != key.bytesize
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

# aesKeyWrap = SyrupPay::Jwa::AesKeyWrap.new(32)
# enc = aesKeyWrap.encryption('1234567890123456123456789012345612345678901234561234567890123456', '9876543210987654987654321098765498765432109876549876543210987654')
# puts Base64.encode64(enc)
# src = aesKeyWrap.decryption('12345678901234561234567890123456', enc)
# puts src

aesKeyWrap = SyrupPay::Jwa::A128Kw.new
enc = aesKeyWrap.encryption('1234567890123456', '9876543210987654')
puts Base64.encode64(enc)
src = aesKeyWrap.decryption('1234567890123456', enc)
puts src

aesKeyWrap = SyrupPay::Jwa::A256Kw.new
enc = aesKeyWrap.encryption('12345678901234561234567890123456', '98765432109876549876543210987654')
puts Base64.encode64(enc)
src = aesKeyWrap.decryption('12345678901234561234567890123456', enc)
puts src


  #
  #   class Aes256keyWrap
  #     KEY_BYTES_LENGTH = 32
  #
  #     include SyrupPay::Jwa::AesKeyWrap
  #
  #     class << self
  #       def encryption(key, cek)
  #         AesKeyWrap.aes_key_wrap(key, cek, KEY_BYTES_LENGTH)
  #       end
  #
  #       def decryption(key, wrapCek)
  #         AesKeyWrap.aes_key_unwrap(key, wrapCek)
  #       end
  #     end
  #   end
  #
  #   class Aes128KeyWrap
  #     KEY_BYTES_LENGTH = 16
  #
  #     include SyrupPay::Jwa::AesKeyWrap
  #
  #     class << self
  #       def encryption(key, cek)
  #         AesKeyWrap.aes_key_wrap(key, cek, KEY_BYTES_LENGTH)
  #       end
  #
  #       def decryption(key, wrapCek)
  #         AesKeyWrap.aes_key_unwrap(key, wrapCek)
  #       end
  #     end
  #   end
  # end
# end
#
# wrapped_key = SyrupPay::Jwa::A128KW.encryption("1234567890123456", "9876543210987654")
#
# puts Base64.encode64(wrapped_key)
#
# src = SyrupPay::Jwa::A128KW.decryption("1234567890123456", wrapped_key)
#
# puts src
#
#
# wrapped_key = SyrupPay::Jwa::A256KW.encryption("12345678901234561234567890123456", "98765432109876549876543210987654")
#
# puts Base64.encode64(wrapped_key)
#
# src = SyrupPay::Jwa::A256KW.decryption("12345678901234561234567890123456", wrapped_key)
#
# puts src

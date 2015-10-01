require 'securerandom'

module SyrupPay
  module Jwa
    module RandomKeyGen
      def randomKey(length)
        SecureRandom.hex(length)
      end
    end

    class ContentEncryptionKeyGenerator
      include SyrupPay::Jwa::RandomKeyGen
      attr_reader :key_length, :cek

      def initialize(key_length)
        @key_length = key_length
      end

      def user_encryption_key=(cek)
        @cek = cek
      end

      def generate_random_key
        if (@cek.nil?)
          @cek = randomKey(@key_length/2)
        end

        @cek
      end
    end
  end
end

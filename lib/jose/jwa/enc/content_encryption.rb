module SyrupPay
  module Jwa
    class ContentEncryption
      include SyrupPay::Jwa::RandomKeyGen
      attr_reader :key_length, :iv_length

      def initialize(key_length, iv_length)
        @key_length = key_length
        @iv_length = iv_length
      end

      def generate_random_iv
        randomKey(@iv_length/2)
      end

      def content_encryption_generator
        SyrupPay::Jwa::ContentEncryptionKeyGenerator.new(@key_length)
      end
    end
  end
end

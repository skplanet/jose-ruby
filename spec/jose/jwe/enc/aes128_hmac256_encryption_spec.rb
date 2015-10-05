require 'rspec'
require 'jose/jwa/enc/aes128_hmac2565_encryption'
require 'url_safe_base64'

describe SyrupPay::Jwa::A128CbcHmac256Encryption do
  context 'when encryption' do
    it 'return with cipher text' do
      payload = [76, 105, 118, 101, 32, 108, 111, 110, 103, 32,
                 97, 110, 100, 32, 112, 114, 111, 115, 112, 101,
                 114, 46].pack('C*')

      cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207].pack('C*')

      iv = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108,
            105, 99, 111, 116, 104, 101].pack('C*')

      aad = UrlSafeBase64.encode64({'alg'=>'A128KW', 'enc'=>'A128CBC-HS256'}.to_json)
      a128cbchmac256encryption = SyrupPay::Jwa::A128CbcHmac256Encryption.new
      cipher_text, at, iv = a128cbchmac256encryption.encrypt_and_sign(cek, iv, payload, aad)

      expect(UrlSafeBase64.encode64(cipher_text)).to eq('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY')
    end
  end

  context 'when decryption' do
    it 'return with expected source and no raise InvalidVerifyError' do
      cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207].pack('C*')

      iv = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108,
            105, 99, 111, 116, 104, 101].pack('C*')

      aad = UrlSafeBase64.encode64({'alg'=>'A128KW', 'enc'=>'A128CBC-HS256'}.to_json)
      cipherText = UrlSafeBase64.decode64('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY')
      expected = 'Live long and prosper.'

      a128cbchmac256encryption = SyrupPay::Jwa::A128CbcHmac256Encryption.new
      actual = a128cbchmac256encryption.verify_and_decrypt(cek, iv, cipherText, aad, 'U0m_YmjN04DJvceFICbCVQ')

      expect(actual).to eq expected
    end
  end

  context 'when verify for wrong authenticated tag' do
    it 'raise InvalidVerifyError' do
      cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207].pack('C*')

      iv = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108,
            105, 99, 111, 116, 104, 101].pack('C*')

      aad = UrlSafeBase64.encode64({'alg'=>'A128KW', 'enc'=>'A128CBC-HS256'}.to_json)
      cipherText = UrlSafeBase64.decode64('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY')
      expected = 'Live long and prosper.'

      a128cbchmac256encryption = SyrupPay::Jwa::A128CbcHmac256Encryption.new
      expect {
        a128cbchmac256encryption.verify_and_decrypt(cek, iv, cipherText, aad, 'U0m_YmjN04DJvceFICbCV1')
      }.to raise_error SyrupPay::Jwa::A128CbcHmac256Encryption::InvalidVerifyError
    end
  end
end

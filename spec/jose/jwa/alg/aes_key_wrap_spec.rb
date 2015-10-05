require 'rspec'
require 'jose/jwa/alg/aes_key_wrap'
require 'jose/jwa/enc/content_encryptionkey_generator'
require 'url_safe_base64'

describe SyrupPay::Jwa::AesKeyWrap do
  context 'when encryption' do
    it 'return with cek and wrapped cek' do
      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg')

      cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207]

      aesKeyWrap = SyrupPay::Jwa::AesKeyWrap.new(16)
      cek, wrapped_cek = aesKeyWrap.encryption(key, cek)

      expect(UrlSafeBase64.encode64(wrapped_cek)).to eq '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ'
    end
  end

  context 'when key length is wrong' do
    it 'raises InvalidKeyLengthError' do
      cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207]

    aesKeyWrap = SyrupPay::Jwa::AesKeyWrap.new(15)
    expect { aesKeyWrap.encryption('12345678901234561234567890123456', cek) }.to raise_error SyrupPay::Jwa::AesKeyWrap::InvalidKeyLengthError
    end
  end

  context 'when decryption' do
    it 'return with unwrapped cek' do
      expected_cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207]

      cek = UrlSafeBase64.decode64('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ')
      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg')

      aesKeyWrap = SyrupPay::Jwa::AesKeyWrap.new(16)
      actual_cek = aesKeyWrap.decryption(key, cek)

      expect(actual_cek).to eq(expected_cek.pack('C*'))
    end
  end
end

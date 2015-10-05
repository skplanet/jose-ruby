require 'rspec'
require 'jose/syruppay_jose'

describe 'JWE' do
  include SyrupPay::JWE

  context '#compact_serialization' do
    it 'matches expected result' do
      cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207].pack('C*')

      iv = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108,
            105, 99, 111, 116, 104, 101].pack('C*')

      payload = [76, 105, 118, 101, 32, 108, 111, 110, 103, 32,
                 97, 110, 100, 32, 112, 114, 111, 115, 112, 101,
                 114, 46].pack('C*')

      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg');

      expected = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ'

      actual = compact_serialization_for_test(key, cek, iv, {'alg' => 'A128KW', 'enc' => 'A128CBC-HS256'}, payload)
      expect(actual).to eq expected
    end
  end

  context '#compact_deserialization' do
    it 'matches expected result' do
      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg');
      jwe_result = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ'

      expected = 'Live long and prosper.'

      actual = compact_deserialization(key, jwe_result)

      expect(actual).to eq expected
    end
  end
end

describe 'JWS' do
  include SyrupPay::JWS

  context '#compact_serialization' do
    it 'matches expected result' do
      claims = "{\"iss\":\"joe\",\n" + "   \"exp\":1300819380,\n" + "   \"http://example.com/is_root\":true}"
      key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

      expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLAogICAiZXhwIjoxMzAwODE5MzgwLAogICAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.NnnMCS7jsU-kBIm3oJIc5xEHLGzzXLX6O2wVxlslAgo"

      actual = compact_serialization(key, {'typ' => 'JWT', 'alg' => 'HS256'}, claims)

      expect(actual).to eq expected
    end
  end

  context '#compact_deserialization' do
    it 'matches expected result' do
      signing = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLAogICAiZXhwIjoxMzAwODE5MzgwLAogICAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.NnnMCS7jsU-kBIm3oJIc5xEHLGzzXLX6O2wVxlslAgo"
      key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

      expected = "{\"iss\":\"joe\",\n" + "   \"exp\":1300819380,\n" + "   \"http://example.com/is_root\":true}"

      actual = compact_deserialization(key, signing)

      expect(actual).to eq expected
    end
  end
end

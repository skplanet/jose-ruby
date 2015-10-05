require 'rspec'
require 'jose/jws/jws'

describe SyrupPay::JwsSerializer do
  context 'when JWS serialize' do
    it 'matches expected result' do
      claims = "{\"iss\":\"joe\",\n" + "   \"exp\":1300819380,\n" + "   \"http://example.com/is_root\":true}"
      key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

      expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLAogICAiZXhwIjoxMzAwODE5MzgwLAogICAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.NnnMCS7jsU-kBIm3oJIc5xEHLGzzXLX6O2wVxlslAgo"

      jwsSerializer = SyrupPay::JwsSerializer.new(key)
      jws_result = jwsSerializer.compactSerialize({'typ' => 'JWT', 'alg' => 'HS256'}, claims)

      expect(jws_result).to eq expected
    end
  end

  context 'when JWS deserialize' do
    it 'matches expected result' do
      signing = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLAogICAiZXhwIjoxMzAwODE5MzgwLAogICAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.NnnMCS7jsU-kBIm3oJIc5xEHLGzzXLX6O2wVxlslAgo"
      key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

      expected = "{\"iss\":\"joe\",\n" + "   \"exp\":1300819380,\n" + "   \"http://example.com/is_root\":true}"

      jwsSerializer = SyrupPay::JwsSerializer.new(key)
      actual = jwsSerializer.compactDeserialize(signing)

      expect(actual).to eq expected
    end
  end
end

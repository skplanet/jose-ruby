require 'rspec'
require 'syruppay_jose'

describe 'JsonEncryptionCompactSerialization' do
  context '#serialization' do
    it 'matches expected result' do
      payload = [76, 105, 118, 101, 32, 108, 111, 110, 103, 32,
                 97, 110, 100, 32, 112, 114, 111, 115, 112, 101,
                 114, 46].pack('C*')

      expected = 'Live long and prosper.'
      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg');

      jwe_token = SyrupPay::JsonEncryptionCompactSerialization.serialization(key, {:alg => 'A128KW', :enc => 'A128CBC-HS256'}, payload)
      actual = SyrupPay::CompactDeserialization.deserialization(key, jwe_token)

      expect(actual).to eq expected
    end
  end

  context '#deserialization' do
    it 'matches expected result' do
      serialize_input = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.InI3AtAH0bTq3uR-CZLOvqDyHt0WKBk9KPauauXysRmRWYqIorgT3Q.NmIzMWFlM2YyODAyYjMwZA.U9vntb16e_EfmPVO7SCrvx1TX4TXNzGMg5Nsw3-stuw.AOZxq-cpYQTASGYxXaogTw'
      expected = 'Live long and prosper.'
      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg');

      actual = SyrupPay::CompactDeserialization.deserialization(key, serialize_input)

      expect(actual).to eq expected
    end
  end
end

describe 'JsonSignatureCompactSerialization' do
  context '#serialization' do
    it 'matches expected result' do
      claims = "{\"iss\":\"joe\",\n" + "   \"exp\":1300819380,\n" + "   \"http://example.com/is_root\":true}"
      expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLAogICAiZXhwIjoxMzAwODE5MzgwLAogICAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.NnnMCS7jsU-kBIm3oJIc5xEHLGzzXLX6O2wVxlslAgo';
      key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

      actual = SyrupPay::JsonSignatureCompactSerialization.serialization(key, {:typ => 'JWT', :alg => 'HS256'}, claims)

      expect(actual).to eq expected
    end
  end

  context '#deserialization' do
    it 'matches expected result' do
      serialized_input = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLAogICAiZXhwIjoxMzAwODE5MzgwLAogICAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.NnnMCS7jsU-kBIm3oJIc5xEHLGzzXLX6O2wVxlslAgo';
      expected = "{\"iss\":\"joe\",\n" + "   \"exp\":1300819380,\n" + "   \"http://example.com/is_root\":true}"
      key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

      actual = SyrupPay::CompactDeserialization.deserialization(key, serialized_input)

      expect(actual).to eq expected
    end
  end
end

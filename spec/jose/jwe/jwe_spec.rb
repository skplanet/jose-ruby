require 'rspec'
require 'jose/jwe/jwe'
require 'url_safe_base64'

describe SyrupPay::JweSerializer do
  context 'when jwe serialize' do
    it 'is matched with expected result' do
      cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
             157, 250, 63, 170, 106, 206, 107, 124, 212, 45,
             111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
             44, 207 ].pack('C*')

      iv = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108,
            105, 99, 111, 116, 104, 101 ].pack('C*')

      payload = [76, 105, 118, 101, 32, 108, 111, 110, 103, 32,
                 97, 110, 100, 32, 112, 114, 111, 115, 112, 101,
                 114, 46 ].pack('C*')

      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg');

      expected = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ'

      jweSerializer = SyrupPay::JweSerializer.new(key)
      jweSerializer.cek = cek
      jweSerializer.iv = iv
      actual = jweSerializer.compactSerialize({'alg'=>'A128KW', 'enc'=>'A128CBC-HS256'}, payload)

      expect(actual).to eq expected
    end
  end

  context 'when jwe deserialize' do
    it 'it matched with expected result' do
      key = UrlSafeBase64.decode64('GawgguFyGrWKav7AX4VKUg');
      jwe_result = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ'

      expected = 'Live long and prosper.'

      jweSerializer = SyrupPay::JweSerializer.new(key)
      actual = jweSerializer.compactDeserialize(jwe_result)

      expect(actual).to eq expected
    end
  end
end

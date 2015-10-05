require 'rspec'
require 'jose/jwa/alg/hmac_sha256_signature'
require 'url_safe_base64'

describe SyrupPay::Jwa::HmacSha256Signature do
  context 'when make signature' do
    it 'matched expected result' do
      hmac_data = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
      key = UrlSafeBase64.decode64('AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow')

      expected = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

      hmacsha256signature = SyrupPay::Jwa::HmacSha256Signature.new
      actual = hmacsha256signature.sign(key, hmac_data)

      expect(UrlSafeBase64.encode64(actual)).to eq expected
    end
  end

  context 'when verify signature' do
    it 'dose not raise InvalidVerifyError' do
      hmac_data = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
      key = UrlSafeBase64.decode64('AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow')
      expected = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

      hmacsha256signature = SyrupPay::Jwa::HmacSha256Signature.new
      expect { hmacsha256signature.verify!(key, hmac_data, expected) }.not_to raise_error
    end
  end
end

# JOSE for SyrupPay

Ruby로 구현한 JOSE(Javascript Object Signing and Encryption) - RFC 7516, RFC 7515 규격입니다. 
JOSE 규격은 SyrupPay 결제 데이터 암복호화 및 AccessToken 발행 등에 사용되며 SyrupPay 서비스의 가맹점에 배포하기 위한 목적으로 라이브러리가 구현되었습니다.

## Supported Ruby version
~>= Ruby 2.0.0

## Installation

```ruby
$ gem install syruppay_jose
```

## Usage

### JWE
```ruby
require syruppay_jose

include SyrupPay::JWE

# SyrupPay가 발급하는 secret
key = '1234567890123456'
# JWE header 규격
# alg : key wrap encryption algorithm. 아래 Supported JOSE encryption algorithms 참조
# enc : content encryption algorithm. 아래 Supported JOSE encryption algorithms 참조
# kid : SyrupPay가 발급하는 iss
header = {'alg'=>'A128KW', 'enc'=>'A128CBC-HS256', 'kid'=>'syruppay_sample'}
# 암호화 할 데이터
payload = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}'

# encryption and serialize
jwe_value = compactSeriaization(key, header, payload}

# decryption and deserialize
actual = compactDeserialization(key, jwe_value)
```

### JWS
```ruby
require syruppay_jose

include SyrupPay::JWS

# SyrupPay가 발급하는 secret
key = '12345678901234561234567890123456'
# JWS header 규격
# alg : signature algorithm. 아래 Supported JOSE encryption algorithms 참조
# kid : SyrupPay가 발급하는 iss
header = {'alg'=>'HS256', 'kid'=>'syruppay_sample'}
# sign 할 데이터
claims = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}' # 

# sign and serialize
jws_value = compactSeriaization(key, header, claims}

# verify and deserialize
actual = compactDeserialization(key, jws_value)
```

## Supported JOSE encryption algorithms

### "alg" (Algorithm) Header Parameter Values For JWE
alg Param Value|Key Management Algorithm
------|------
A128KW|AES Key Wrap with default initial value using 128 bit key
A256KW|AES Key Wrap with default initial value using 256 bit key

### "enc" (Encryption Algorithm) Header Parameter Values for JWE
enc Param Value|Content Encryption Algorithm
-------------|------
A128CBC-HS256|AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm

### "alg" (Algorithm) Header Parameter Values for JWS
alg Param Value|Digital Signature or MAC Algorithm
-----|-------
HS256|HMAC using SHA-256

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).


# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'jose/version'

Gem::Specification.new do |spec|
  spec.name          = "syruppay_jose"
  spec.version       = SyrupPay::Jose::VERSION
  spec.authors       = ["byeongchan"]
  spec.email         = ["byeongchan.park@sk.com"]

  spec.summary       = %q{JOSE for SyrupPay service's merchant}
  spec.description   = %q{Library for SyrupPay service's merchant.
                        This is implemented JOSE specification, RFC 7515, 7516.
                        support algorithm : JWE-A128KW, A256KW, A128CBC-HS256, JWS-HS256}
  spec.homepage      = "https://github.com/skplanet/jose-ruby"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = "~> 2.0"

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.3"
  spec.add_runtime_dependency  "aes_key_wrap", "1.0.1"
  spec.add_runtime_dependency  "bindata", "~> 2.1"
  spec.add_runtime_dependency  "activesupport", "4.2.4"
  spec.add_runtime_dependency  "url_safe_base64", "~> 0.2.2"
end

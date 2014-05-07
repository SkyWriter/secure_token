# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'secure_token/version'

Gem::Specification.new do |spec|
  spec.name          = "secure_token"
  spec.version       = SecureToken::VERSION
  spec.authors       = ["Ivan Kasatenko"]
  spec.email         = ["sky.31338@gmail.com"]
  spec.summary       = %q{JWT-like solution, that enables you to store encrypted and signed Hash'es on the client side, decrypt and verify them upon retreival}
  spec.homepage      = "https://github.com/SkyWriter/secure_token"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'activesupport'
  spec.add_development_dependency "bundler", "~> 1.5"
  spec.add_development_dependency "rake"
end

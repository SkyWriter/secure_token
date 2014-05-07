# SecureToken

Gem that provides JWT token like solution. You can convert any hash into
a string that is suitable for storage at the client-side. It is
URL-safe, encrypted and digitally signed.

## Installation

Add this line to your application's Gemfile:

    gem 'secure_token'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install secure_token

## Usage

```ruby
    require 'secure_token'

    data = SecureToken::SecureTokenHash.new

    data.merge!({
      key: 'value',
      another: {
        place: 1,
        subdata: [ 4, 5, 6 ]
      }
    })

    key = SecureToken::KeyPair.new('s3cret', 'service')

    encrypted = data.to_token(key)
    # encrypted is url-safe
    # looks like "0qaai-mRZZY0WMJci13QST11UI80NiSc9YXb4ABW-pgauFH2wDtDpbH7Vm408BOP5xlq2jO3Srz_WqDlehi1AYP3VtFoUdtNtjuvObess0Lh35Yml1opZ2QOlJ2brwmjNxNWsEoC6JMsdzMUSuF-1JrQwvarPC5B"

    decrypted = SecureToken::SecureTokenHash.from_token(encrypted, key)
    # assert(decrypted == data)

    invalid_key = SecureToken::KeyPair.new('secret', 'serv1ce')
    not_decrypted = SecureToken::SecureTokenHash.from_token(encrypted, invalid_key)
    # assert(not_decrypted == nil)
```

## Contributing

1. Fork it ( http://github.com/skywriter/secure_token/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

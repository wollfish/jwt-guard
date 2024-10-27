# JWTGuard

JWTGuard is a Ruby gem for handling user authentication using JSON Web Tokens (JWT). It provides a simple interface for
encoding and decoding JWTs with built-in validation options to ensure secure authentication.

---

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'jwt_guard'
```

Then, execute:

```shell
bundle install
```

Or install it yourself as:

```shell
gem install jwt_guard
```

---

## Configuration

JWTGuard relies on several environment variables for configuration:

- `JWT_ISSUER`: The issuer of the JWT.
- `JWT_AUDIENCE`: The audience for the JWT (comma-separated if multiple).
- `JWT_ALGORITHM`: The algorithm used for signing (default is RS256).
- `JWT_DEFAULT_LEEWAY`: The default leeway for expiration validation (optional).
- `JWT_ISSUED_AT_LEEWAY`: Leeway for issued-at time (optional).
- `JWT_EXPIRATION_LEEWAY`: Leeway for expiration time (optional).
- `JWT_NOT_BEFORE_LEEWAY`: Leeway for not-before time (optional).

Make sure to set these environment variables in your application.

---

## Usage

Initializing the Authenticator
You can create an instance of the JWTGuard::Authenticator by providing a public and private key:

```ruby
rsa_private = OpenSSL::PKey::RSA.generate(2048)
authenticator = JWTGuard::Authenticator.new(rsa_private.public_key, rsa_private.private_key)
```

### Encoding a Token

To encode a JWT with a payload, use the encode method:

```ruby
payload = { uid: "123", role: "admin", jti: SecureRandom.uuid }

token = authenticator.encode(payload)
puts token
```

### Authenticating a Token

To authenticate a token, use the authenticate! method:

```ruby

begin
  decoded_payload = authenticator.authenticate!("Bearer #{token}")
  puts decoded_payload

rescue JWTGuard::Error => e
  puts e.message
end
```

### Example Token validation

```ruby
rsa_private = OpenSSL::PKey::RSA.generate(2048)
rsa_public_key = rsa_private.public_key

payload = {
  :iat => Time.now.to_i,
  :exp => (Time.zone.now + 60).to_i,
  :sub => "session",
  :iss => "abc",
  :aud => ["xyz"],
  :jti => SecureRandom.uuid,
  :email => "user@example.com",
  :uid => "ID0AC0308",
  :role => "admin",
  :level => 6,
  :state => "active",
  :full_name => "Pa School teacher",
  :country_code => "IND"
}

token = JWT.encode(payload, rsa_private, "RS256")

authenticator = JWTGuard::Authenticator.new(rsa_public_key)
authenticator.authenticate!("Bearer #{token}")
```

---

## Error Handling

JWTGuard raises specific errors for different failure scenarios:

- `JWTGuard::Error`: General error for authorization failures. `OR` Raised when decoding fails due to invalid tokens.

---

## Testing

To ensure that your installation works correctly, you can run the RSpec tests included with the gem. If RSpec is set up
in your project, run:

```shell
rspec
```

---

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/wollfish/jwt-guard.

---

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

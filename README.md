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
encode_options = { algorithm: "RS256", aud: %w[pqr xyz], exp: "60", iss: "abc" }
verify_options = { algorithms: %w[RS256 RS384 RS512], aud: %w[pqr xyz], iss: "abc" }

authenticator = JWTGuard::Authenticator.new(
  private_key: rsa_private.private_key,
  public_key: rsa_private.public_key,
  encode_options: encode_options,
  verify_options: verify_options
)
```

### Encoding a Token

To encode a JWT with a payload, use the encode method:

```ruby
payload = { uid: "123", role: "admin", jti: SecureRandom.hex(10) }

token = authenticator.encode!(payload)
puts token
```

### Authenticating a Token

To authenticate a token, use decode! method:

```ruby
begin
  decoded_payload = authenticator.decode!(token)
  puts decoded_payload

rescue JWTGuard::Error => e
  puts e.message
end
```

### Example Token validation

```ruby
rsa_private = OpenSSL::PKey::RSA.generate(2048)

payload = {
  jti: SecureRandom.hex(10),
  uid: "ID0AC0308",
  email: "user@example.com",
  role: "admin",
  level: 6,
  state: "active"
}

token = JWT.encode(
  payload.merge(iat: Time.now.to_i, exp: (Time.now + 60).to_i, sub: "any", iss: "abc", aud: ["xyz"]),
  rsa_private,
  "RS256"
)

encode_options = { algorithm: "RS256", aud: %w[pqr xyz], exp: "60", iss: "abc" }
verify_options = { algorithms: %w[RS256 RS384 RS512], aud: %w[pqr xyz], iss: "abc" }

auth = JWTGuard::Authenticator.new(
  private_key: rsa_private.private_key,
  public_key: rsa_private.public_key,
  encode_options: encode_options,
  verify_options: verify_options
)

auth.encode!(payload)
auth.decode!(token)
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

# frozen_string_literal: true

require "jwt"

module JWTGuard
  # Authenticator handles user authentication using JWT tokens.
  #
  # Configurable through ENV variables:
  # * JWT_DEFAULT_LEEWAY, JWT_ISSUED_AT_LEEWAY, JWT_EXPIRATION_LEEWAY, JWT_NOT_BEFORE_LEEWAY
  #
  # @see https://github.com/jwt/ruby-jwt for detailed validation options.
  #
  # @example Token validation
  #   rsa_private = OpenSSL::PKey::RSA.generate(2048)
  #
  #   default_payload = {
  #     aud: ["xyz"], exp: (Time.now + 60).to_i, iat: Time.now.to_i,
  #     iss: "abc", jti: SecureRandom.hex(10), sub: "any"
  #   }
  #
  #   payload = {
  #     uid: "ID0AC0308",
  #     email: "user@example.com",
  #     role: "admin",
  #     level: 6,
  #     state: "active"
  #   }
  #
  #   JWT.encode(default_payload.merge(payload), rsa_private, "RS256")
  #
  #   encode_options = { algorithm: "RS256", aud: %w[pqr xyz], exp: "60", iss: "abc" }
  #   decode_options = { algorithms: %w[RS256 RS384 RS512], aud: %w[pqr xyz], iss: "abc" }
  #
  #   auth = JWTGuard::Authenticator.new(
  #     private_key: rsa_private.private_key,
  #     public_key: rsa_private.public_key,
  #     encode_options: encode_options,
  #     decode_options: decode_options
  #   )
  #
  #   auth.encode!(payload)
  #   auth.decode!(token)
  class Authenticator
    # Initializes the Authenticator with public and private keys.
    #
    # @param private_key [OpenSSL::PKey::PKey, nil] Private key for token encoding.
    # @param public_key [OpenSSL::PKey::PKey, nil] Public key for token verification.
    # @param encode_options [Hash] Encode Option.
    # @param decode_options [Hash] Verify Option.
    def initialize(private_key: nil, public_key: nil, encode_options: {}, decode_options: {})
      @public_key = public_key
      @private_key = private_key
      @encode_options = { algorithm: "RS256" }.merge(encode_options)
      @decode_options = { algorithms: ["RS256"], sub: "any" }.merge(build_decode_options).merge(decode_options)
    end

    # Encodes a payload as a JWT token using the private key.
    #
    # @param payload [Hash] The payload to encode in the JWT.
    # @return [String] The encoded JWT token.
    # @raise [ArgumentError] If the private key is not provided.
    def encode!(payload)
      raise ArgumentError, "No private key given." unless @private_key

      encode_payload = {
        aud: @encode_options.fetch(:aud, []),
        exp: (Time.now + @encode_options.fetch(:exp, "60").to_i).to_i,
        iat: Time.now.to_i,
        iss: @encode_options[:iss],
        jti: SecureRandom.hex(10),
        sub: @encode_options.fetch(:sub, "any")
      }

      JWT.encode(encode_payload.merge(payload), @private_key, @encode_options[:algorithm])
    end

    # Decodes and verifies the JWT token value.
    #
    # @param token [String] The actual JWT token value to decode.
    # @param option [Hash] The verification option used to decode.
    #
    # @return [Hash] The decoded payload as a hash with symbolized keys.
    # @raise [JWTGuard::Error] If decoding or verification fails.
    def decode!(token, option: {})
      raise ArgumentError, "No public key given." unless @public_key

      payload, _header = JWT.decode(token, @public_key, true, @decode_options.merge(option))

      payload
    rescue JWT::DecodeError => e
      raise JWTGuard::Error, "JWT verification failed: #{e.message}"
    end

    private

    # Builds complete JWT verification options by merging core and audience options.
    #
    # @return [Hash] The complete JWT verification options.
    def build_decode_options
      {
        verify_aud: true,
        verify_expiration: true,
        verify_iat: true,
        verify_iss: true,
        verify_jti: true,
        verify_not_before: true,
        verify_sub: true
      }.merge(leeway_options).compact
    end

    # Constructs leeway options from environment variables.
    #
    # @return [Hash] Leeway options for JWT verification.
    def leeway_options
      {
        leeway: ENV["JWT_DEFAULT_LEEWAY"]&.to_i,
        iat_leeway: ENV["JWT_ISSUED_AT_LEEWAY"]&.to_i,
        exp_leeway: ENV["JWT_EXPIRATION_LEEWAY"]&.to_i,
        nbf_leeway: ENV["JWT_NOT_BEFORE_LEEWAY"]&.to_i
      }
    end
  end
end

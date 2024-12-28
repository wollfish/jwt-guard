# frozen_string_literal: true

require "jwt"

module JWTGuard
  # Authenticator handles user authentication using JWT tokens.
  #
  # Configurable through ENV variables:
  # * JWT_ISSUER, JWT_AUDIENCE, JWT_ALGORITHM (default: RS256)
  # * JWT_DEFAULT_LEEWAY, JWT_ISSUED_AT_LEEWAY, JWT_EXPIRATION_LEEWAY, JWT_NOT_BEFORE_LEEWAY
  #
  # @see https://github.com/jwt/ruby-jwt for detailed validation options.
  #
  # @example Token validation
  #   rsa_private = OpenSSL::PKey::RSA.generate(2048)
  #   rsa_public_key = rsa_private.public_key
  #
  #   payload = {
  #     :iat=>Time.now.to_i,
  #     :exp=>(Time.zone.now + 60).to_i,
  #     :sub=>"session",
  #     :iss=>"abc",
  #     :aud=>["xyz"],
  #     :jti=>"8c5ee641e29b94717b56",
  #     :email=>"user@example.com",
  #     :uid=>"ID0AC0308",
  #     :role=>"admin",
  #     :level=>6,
  #     :state=>"active",
  #     :full_name=>"Pa School teacher",
  #     :country_code=>"IND"
  #   }
  #
  #   token = JWT.encode(payload, rsa_private, "RS256")
  #
  #   auth = JWTGuard::Authenticator.new(rsa_public_key)
  #   auth.decode!(token)
  class Authenticator
    # Initializes the Authenticator with public and private keys.
    #
    # @param private_key [OpenSSL::PKey::PKey, nil] Private key for token encoding.
    # @param public_key [OpenSSL::PKey::PKey, nil] Public key for token verification.
    def initialize(private_key: nil, public_key: nil)
      @public_key = public_key
      @private_key = private_key
      @verify_options = build_verify_options
      @encode_options = { algorithm: @verify_options[:algorithms].first }.compact
    end

    # Encodes a payload as a JWT token using the private key.
    #
    # @param payload [Hash] The payload to encode in the JWT.
    # @return [String] The encoded JWT token.
    # @raise [ArgumentError] If the private key is not provided.
    def encode!(payload)
      raise ArgumentError, "No private key given." unless @private_key

      encode_payload = {
        aud: ENV["JWT_AUDIENCE"]&.split(",") || [],
        exp: (Time.now + 60).to_i,
        iat: Time.now.to_i,
        iss: ENV.fetch("JWT_ISSUER", nil),
        jti: SecureRandom.hex(10),
        sub: 'session'
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

      payload, _header = JWT.decode(token, @public_key, true, @verify_options.merge(option))

      payload
    rescue JWT::DecodeError => e
      raise JWTGuard::Error, "JWT verification failed: #{e.message}"
    end

    private

    # Builds complete JWT verification options by merging core and audience options.
    #
    # @return [Hash] The complete JWT verification options.
    def build_verify_options
      {
        algorithms: [ENV.fetch("JWT_ALGORITHM", "RS256")],
        aud: ENV["JWT_AUDIENCE"]&.split(",") || [],
        iss: ENV.fetch("JWT_ISSUER", nil),
        sub: "session"
      }.merge(core_verify_options).merge(leeway_options).compact
    end

    # Builds JWT verification options from environment variables.
    #
    # @return [Hash] The core JWT verification options.
    def core_verify_options
      {
        verify_aud: !ENV["JWT_AUDIENCE"].nil? && !ENV["JWT_AUDIENCE"].empty?,
        verify_expiration: true,
        verify_iat: true,
        verify_iss: !ENV["JWT_ISSUER"].nil? && !ENV["JWT_ISSUER"].empty?,
        verify_jti: true,
        verify_not_before: true,
        verify_sub: true
      }
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

# frozen_string_literal: true

require "jwt"
require "securerandom"

require_relative "../../lib/jwt_guard/authenticator"

RSpec.describe JWTGuard::Authenticator do
  let(:public_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:private_key) { public_key }
  let(:authenticator) { described_class.new(public_key, private_key) }
  let(:payload) { { user_id: 1, sub: "session", jti: SecureRandom.uuid } }
  let(:token) { "Bearer #{authenticator.encode(payload)}" }

  describe "#authenticate!" do
    context "with valid token" do
      it "decodes and verifies the token" do
        result = authenticator.authenticate!(token)

        expect(result["user_id"]).to eq(1)
        expect(result["sub"]).to eq("session")
        expect(result["jti"]).to eq(payload[:jti])
      end
    end

    context "with invalid token type" do
      it "raises an error" do
        expect { authenticator.authenticate!("Invalid token") }
          .to raise_error(JWTGuard::Error, "Authorization failed: Invalid token type.")
      end
    end

    context "with expired token" do
      it "raises a JWTGuard::Error" do
        expired_payload = payload.merge(exp: Time.now.to_i - 3600)
        expired_token = "Bearer #{JWT.encode(expired_payload, private_key, "RS256")}"

        expect { authenticator.authenticate!(expired_token) }.to raise_error(JWTGuard::Error, /JWT verification failed/)
      end
    end
  end

  describe "#encode" do
    context "without a private key" do
      it "raises an ArgumentError" do
        authenticator = described_class.new(public_key)

        expect { authenticator.encode(payload) }.to raise_error(ArgumentError, "No private key given.")
      end
    end
  end
end

# frozen_string_literal: true

module JWTGuard
  # Custom error class for JWTGuard authorization errors.
  class Error < StandardError
    # Initializes the error with a custom reason.
    #
    # @param reason [String] The reason for the authorization failure.
    def initialize(reason = "")
      super("Authorization failed: #{reason}")
    end
  end
end

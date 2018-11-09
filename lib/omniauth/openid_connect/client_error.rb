module OmniAuth
  module OpenIDConnect
    class ClientError < ::StandardError; end

    # Specific error types
    class RefreshTokenInvalidGrant < ClientError; end
  end
end
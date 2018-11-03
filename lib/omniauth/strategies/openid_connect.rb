require 'addressable/uri'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy

      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        scheme: 'https',
        host: nil,
        port: 443,
        authorization_endpoint: '/authorize',
        token_endpoint: '/token',
        userinfo_endpoint: '/userinfo',
        jwks_uri: '/jwk',
        end_session_endpoint: nil
      }
      option :issuer
      option :discovery, false
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, "code"
      option :state
      option :response_mode
      option :display, nil #, [:page, :popup, :touch, :wap]
      option :prompt, nil #, [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :acr_values
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method
      option :post_logout_redirect_uri

      uid { user_info.sub }

      info do
        {
          name: user_info.name,
          email: user_info.email,
          nickname: user_info.preferred_username,
          first_name: user_info.given_name,
          last_name: user_info.family_name,
          gender: user_info.gender,
          image: user_info.picture,
          phone: user_info.phone_number,
          urls: { website: user_info.website }
        }
      end

      extra do
        { raw_info: user_info.raw_attributes }
      end

      credentials do
        {
          id_token: access_token.id_token,
          token: access_token.access_token,
          refresh_token: access_token.refresh_token,
          expires_in: access_token.expires_in,
          scope: access_token.scope
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def config
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)
      end

      def request_phase
        discover!
        redirect authorize_uri
      end

      def callback_phase
        error = request.params['error_reason'] || request.params['error']
        if error
          raise CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
        elsif request.params['state'].to_s.empty? || request.params['state'] != stored_state
          return Rack::Response.new(['401 Unauthorized'], 401).finish
        elsif !request.params['code']
          return fail!(:missing_code, OmniAuth::OpenIDConnect::MissingCodeError.new(request.params['error']))
        else
          discover!
          client.redirect_uri = redirect_uri
          client.authorization_code = authorization_code
          access_token
          super
        end
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      # RP-Initiated Logout
      # https://openid.net/specs/openid-connect-session-1_0.html#rfc.section.5
      #
      # Rails Example:
      # redirect_to "/auth/omni_oidc/logout?#{{id_token_hint: session['omni_oidc.id_token']}.to_param}"
      #
      def logout_phase
        # Discover to initialize the end_session_endpoint
        discover!

        # Fetch the id_token_hint from the request.params to send with redirect to the endsession endpoint
        _id_token = request.params['id_token_hint']

        if end_session_endpoint_is_valid? && _id_token
          log(:info, "RP-Initiated Logout, redirecting to: #{client_options.end_session_endpoint}")
          return redirect(end_session_uri(_id_token))
        end

        # return back nothing if the logout phase has been call but is invalid (should not be)
        log(:error, "Failed to start RP-Initiated Logout.")
        return
      end

      def other_phase
        # Logout Phase
        if logout_path_pattern.match(current_path)
          # Is the current path matching the omniauth local endpoint (request_path + '/logout')
          logout_phase_response = logout_phase
          # If there is no response from the logout phase then do not return, allowing call_app! to be called.
          return logout_phase_response if logout_phase_response
        end
        
        call_app!
      end

      def authorization_code
        request.params['code']
      end

      def end_session_uri(id_token=nil)
        return unless end_session_endpoint_is_valid?
        end_session_uri = URI(client_options.end_session_endpoint)
        end_session_uri.query = encoded_end_session_uri_query(id_token)
        end_session_uri.to_s
      end

      def authorize_uri
        client.redirect_uri = redirect_uri
        opts = {
          response_type: options.response_type,
          scope: options.scope,
          state: new_state,
          login_hint: request.params['login_hint'],
          ui_locales: request.params['ui_locales'],
          claims_locales: request.params['claims_locales'],
          prompt: request.params['prompt'],
          nonce: (new_nonce if options.send_nonce),
          hd: options.hd,
        }
        client.authorization_uri(opts.reject { |k, v| v.nil? })
      end

      def public_key
        return config.jwks if options.discovery
        key_or_secret
      end

      private

      def issuer
        resource = "#{ client_options.scheme }://#{ client_options.host }"
        resource = "#{ resource }:#{ client_options.port }" if client_options.port
        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        return unless options.discovery
        options.issuer = issuer if options.issuer.blank?
        setup_client_options(config)
      end

      def setup_client_options(discover)
        client_options.authorization_endpoint = discover.authorization_endpoint
        client_options.token_endpoint = discover.token_endpoint
        client_options.userinfo_endpoint = discover.userinfo_endpoint
        client_options.jwks_uri = discover.jwks_uri
        client_options.end_session_endpoint = discover.end_session_endpoint
      end

      def user_info
        @user_info ||= access_token.userinfo!
      end

      def access_token
        @access_token ||= begin
          authentication_response = client.access_token!(
            scope: (options.scope if options.send_scope_to_token_endpoint),
            client_auth_method: options.client_auth_method
          )

          _id_token = decode_id_token authentication_response.id_token
          _id_token.verify!(
            issuer: options.issuer,
            client_id: client_options.identifier,
            nonce: stored_nonce
          )

          # return the full authentication response aka: access token
          authentication_response
        end
      end

      def decode_id_token(id_token)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, public_key)
      end

      def client_options
        options.client_options
      end

      def new_state
        state = options.state.call if options.state.respond_to? :call
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def session
        return {} if @env.nil?
        super
      end

      def key_or_secret
        case options.client_signing_alg
        when :HS256, :HS384, :HS512
          return client_options.secret
        when :RS256, :RS384, :RS512
          if options.client_jwk_signing_key
            return parse_jwk_key(options.client_jwk_signing_key)
          elsif options.client_x509_signing_key
            return parse_x509_key(options.client_x509_signing_key)
          end
        else
        end
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end

      def parse_jwk_key(key)
        json = JSON.parse(key)
        if json.has_key?('keys')
          JSON::JWK::Set.new json['keys']
        else
          JSON::JWK.new json
        end
      end

      def decode(str)
        UrlSafeBase64.decode64(str).unpack('B*').first.to_i(2).to_s
      end

      def redirect_uri
        return client_options.redirect_uri unless request.params['redirect_uri']
        "#{ client_options.redirect_uri }?redirect_uri=#{ CGI.escape(request.params['redirect_uri']) }"
      end

      # def is_id_token_valid?(id_token, expected = {})
      #   return false unless id_token
      #   _decoded_id_token = id_token.kind_of?(::OpenIDConnect::ResponseObject::IdToken)? id_token : decode_id_token(id_token)
      #
      #   return false unless _decoded_id_token.exp.to_i > Time.now.to_i
      #   return false unless _decoded_id_token.iss == (options.issuer || expected[:issuer])
      #   # aud(ience) can be a string or an array of strings
      #   unless Array(_decoded_id_token.aud).include?(client_options.identifier || expected[:client_id])
      #     return false
      #   end
      #
      #   true
      # end
      
      def encoded_end_session_uri_query(id_token)
        end_session_query_hash={}
        end_session_query_hash[:id_token_hint] = id_token
        end_session_query_hash[:post_logout_redirect_uri] = options.post_logout_redirect_uri if is_valid_url? options.post_logout_redirect_uri
        URI.encode_www_form(end_session_query_hash)
      end

      def end_session_endpoint_is_valid?
        client_options.end_session_endpoint != nil
      end

      def logout_path_pattern
        %r{\A#{Regexp.quote(request_path)}(/logout)}
      end

      def is_valid_url?(url)
        return false unless url
        uri = URI.parse(url)
        uri.kind_of?( URI::HTTPS ) || uri.kind_of?( URI::HTTP )
      rescue URI::InvalidURIError => e
        log(:error, e.message)
        false
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason=nil, error_uri=nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'

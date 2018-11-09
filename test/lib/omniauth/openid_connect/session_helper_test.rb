require 'test_helper'

module OmniAuth
  module OpenIDConnect
    class SessionHelperTest < MiniTest::Test
      include SessionHelper

      def setup
        @provider_name = :provider_connect
      end

      def test_omniauth_access_token_key
        assert_equal 'openid_connect.provider_connect.access_token', omniauth_access_token_key(@provider_name)
        assert_nil omniauth_access_token_key(nil)
      end

      def test_omniauth_expires_at_key
        assert_equal 'openid_connect.provider_connect.expires_at', omniauth_expires_at_key(@provider_name)
        assert_nil omniauth_expires_at_key(nil)
      end

      def test_omniauth_id_token_key
        assert_equal 'openid_connect.provider_connect.id_token', omniauth_id_token_key(@provider_name)
        assert_nil omniauth_id_token_key(nil)
      end

      def test_omniauth_refresh_expires_at_key
        assert_equal 'openid_connect.provider_connect.refresh_expires_at', omniauth_refresh_expires_at_key(@provider_name)
        assert_nil omniauth_refresh_expires_at_key(nil)
      end

      def test_omniauth_refresh_token_key
        assert_equal 'openid_connect.provider_connect.refresh_token', omniauth_refresh_token_key(@provider_name)
        assert_nil omniauth_refresh_token_key(nil)
      end

      def test_omniauth_scope_key
        assert_equal 'openid_connect.provider_connect.scope', omniauth_scope_key(@provider_name)
        assert_nil omniauth_scope_key(nil)
      end

      def test_omniauth_token_type_key
        assert_equal 'openid_connect.provider_connect.token_type', omniauth_token_type_key(@provider_name)
        assert_nil omniauth_token_type_key(nil)
      end

    end
  end
end
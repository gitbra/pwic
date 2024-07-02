<script>
	'use strict';

	function login_translate_langs(mapping) {
		$('#login_language OPTION').each((i, e) => {
			var lang = $(e).attr('value');
			if (mapping.hasOwnProperty(lang))
				$(e).html(lang + ' - ' + mapping[lang]);
		});
	}

	function login_anonymous() {
		$('#login_user').val('{{pwic.constants.anonymous_user|escape}}');
		$('#login_password').val('');
		$('#login_pin').val('');
		$('#login_form')[0].submit();
		return true;
	}

{% if pwic.env.base_url and pwic.env.oauth_provider %}
	function login_oauth() {
		{% if pwic.env.oauth_provider.value == 'github' %}
			var args = {client_id:		'{{pwic.env.oauth_identifier.value|escape}}',
						redirect_uri:	'{{pwic.env.base_url.value|escape}}/api/oauth',
						login:			$('#login_user').val(),
						scope:			'user:email',
						state:			'{{pwic.oauth_user_secret|escape}}',
						allow_signup:	false};
			window.location = 'https://github.com/login/oauth/authorize?' + (new URLSearchParams(args).toString());

		{% elif pwic.env.oauth_provider.value == 'google' %}
			var args = {client_id:		'{{pwic.env.oauth_identifier.value|escape}}',
						redirect_uri:	'{{pwic.env.base_url.value|escape}}/api/oauth',
						scope:			'https://www.googleapis.com/auth/userinfo.email',
						access_type:	'online',
						state:			'{{pwic.oauth_user_secret|escape}}',
						login_hint:		$('#login_user').val(),
						response_type:	'code'};
			window.location = 'https://accounts.google.com/o/oauth2/v2/auth?' + (new URLSearchParams(args).toString());

		{% elif pwic.env.oauth_provider.value == 'microsoft' %}
			var args = {client_id:		'{{pwic.env.oauth_identifier.value|escape}}',
						response_type:	'code',
						redirect_uri:	'{{pwic.env.base_url.value|escape}}/api/oauth',
						scope:			'https://graph.microsoft.com/user.read',
						response_mode:	'query',
						state:			'{{pwic.oauth_user_secret|escape}}',
						login_hint:		$('#login_user').val()};
			{% if pwic.env.oauth_domains %}
				var main = '{{pwic.env.oauth_domains.value|escape}}'.trim().split(' ')[0];
				if (main.length > 0)
					args['domain_hint'] = main;
			{% endif %}
			window.location = 'https://login.microsoftonline.com/{{pwic.env.oauth_tenant.value|urlencode}}/oauth2/v2.0/authorize?' + (new URLSearchParams(args).toString());

		{% else %}
			throw 'Internal error - Invalid OAuth provider';
		{% endif %}
	}
{% endif %}

{% if pwic.env.registration_link %}
	function login_register() {
		window.location = '{{pwic.env.registration_link.value|escape}}';
		return true;
	}
{% endif %}

	if (window.fetch)
		$('#login_js').addClass('pwic_hidden');
</script>

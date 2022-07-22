<script>
	'use strict';

	function login_translate_langs(mapping) {
		$('#login_language OPTION').each(function(index, element) {
			var lang = $(element).attr('value');
			if (mapping.hasOwnProperty(lang))
				$(element).html(lang + ' - ' + mapping[lang])
		});
	}

	function login_anonymous() {
		$('#login_user').val('{{pwic.constants.anonymous_user|escape}}');
		$('#login_password').val('');
		$('#login_form')[0].submit();
		return true;
	}

{% if pwic.env.oauth_provider %}
	function login_oauth() {
		{% if pwic.env.oauth_provider.value == 'github' %}
			window.location = 'https://github.com/login/oauth/authorize' +
								'?client_id={{pwic.env.oauth_identifier.value|urlencode}}' +
								'&redirect_uri='+encodeURIComponent('{{pwic.env.base_url.value}}/api/oauth') +
								'&login='+encodeURIComponent($('#login_user').val()) +
								'&scope=user%3Aemail' +
								'&state={{pwic.oauth_user_secret|urlencode}}' +
								'&allow_signup=false';

		{% elif pwic.env.oauth_provider.value == 'google' %}
			window.location = 'https://accounts.google.com/o/oauth2/v2/auth' +
								'?client_id={{pwic.env.oauth_identifier.value|urlencode}}' +
								'&redirect_uri='+encodeURIComponent('{{pwic.env.base_url.value}}/api/oauth') +
								'&scope='+encodeURIComponent('https://www.googleapis.com/auth/userinfo.email') +
								'&access_type=online' +
								'&state={{pwic.oauth_user_secret|urlencode}}' +
								'&login_hint='+encodeURIComponent($('#login_user').val()) +
								'&response_type=code';

		{% elif pwic.env.oauth_provider.value == 'microsoft' %}
			var url = 'https://login.microsoftonline.com/{{pwic.env.oauth_tenant.value|urlencode}}/oauth2/v2.0/authorize?' +
						'?client_id={{pwic.env.oauth_identifier.value|urlencode}}' +
						'&response_type=code' +
						'&redirect_uri='+encodeURIComponent('{{pwic.env.base_url.value}}/api/oauth') +
						'&scope='+encodeURIComponent('https://graph.microsoft.com/user.read') +
						'&response_mode=query' +
						'&state={{pwic.oauth_user_secret|urlencode}}' +
						'&login_hint='+encodeURIComponent($('#login_user').val());
			{% if pwic.env.oauth_domains %}
				var main = '{{pwic.env.oauth_domains.value|escape}}'.trim().split(' ')[0];
				if (main.length > 0)
					url += '&domain_hint='+encodeURIComponent(main);
			{% endif %}
			window.location = url;

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
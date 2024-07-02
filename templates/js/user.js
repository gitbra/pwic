<script>
	'use strict';

	function user_password_popup() {
		$('#user_password_popup').toggleClass('pwic_hidden');
		if ($('#user_password_popup').hasClass('pwic_hidden'))
			$('#user_password_current, #user_password_new1, #user_password_new2').val('');
		else
			document.getElementById('user_password_current').focus();
		return false;
	}

	$('body').on('keydown', event => {
		if ((event.key == 'Escape') && (!$('#user_password_popup').hasClass('pwic_hidden')))
			user_password_popup();
	});

	function user_password_submit() {
		var	cur  = $('#user_password_current').val(),
			new1 = $('#user_password_new1').val(),
			new2 = $('#user_password_new2').val();
		if (([cur, new1, new2].indexOf('') !== -1) || (new1 != new2) || (new1 == cur))
			alert({% trans %}'The form is inconsistent.'{% endtrans %});
		else {
			fetch('/api/user/password/change', {method: 'POST',
												headers: {'Content-Type': 'application/x-www-form-urlencoded'},
												body: new URLSearchParams({	password_current: cur,
																			password_new1: new1,
																			password_new2: new2}),
												credentials: 'same-origin' })
				.then(response => {
					if (!response.ok) {
						document.getElementById('user_password_new1').focus();
						throw Error({% trans %}'Failure to save your new password. Verify that it matches with the security rules.'{% endtrans %} + ' ['+response.status+']');
					}
					user_password_popup();
					$('#user_password_status').html('{{pwic.emojis.green_check}}');
					alert({% trans %}'Your password has been changed successfully.'{% endtrans %});
				})
				.catch(error => alert(error));
		}
	}

	function user_language_set() {
		fetch('/api/user/language/set', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body: new URLSearchParams({language: $('#user_language').val()}),
											credentials: 'same-origin' })
			.then(response => { if (response.ok) location.reload() });
	}
</script>

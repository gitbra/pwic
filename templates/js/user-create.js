<script>
	'use strict';

	function create_submit() {
		var	project = $('#create_project').val(),
			user = $('#create_user').val().trim().toLowerCase();
		if ((project == '') || (user.substring(0, 4) == 'pwic'))
			alert({% trans %}'The parameters are not acceptable.'{% endtrans %});
		else {
			$('INPUT[type=button]').attr('disabled', '');
			fetch('/api/user/create', {	method: 'POST',
										headers: {'Content-Type': 'application/x-www-form-urlencoded'},
										body: new URLSearchParams({	project: project,
																	user: user}),
										credentials: 'same-origin'})
				.then(response => {
					$('INPUT[type=button]').removeAttr('disabled');
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					window.location = '/' + project + '/special/roles';
				})
				.catch(error => {
					alert(error);
					$('INPUT[type=button]').removeAttr('disabled');
				});
		}
	}
</script>

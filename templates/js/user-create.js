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
										body:	'project='+encodeURIComponent(project)+
												'&user='+encodeURIComponent(user),
										credentials: 'same-origin' })
				.then(function(response) {
					$('INPUT[type=button]').removeAttr('disabled');
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					else
						window.location = '/'+project+'/special/roles';
				})
				.catch(function(error) {
					alert(error);
					$('INPUT[type=button]').removeAttr('disabled');
				});
		}
	}
</script>
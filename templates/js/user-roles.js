<script>
	'use strict';

	function roles_toggle(id, project, user, role) {
		var element = $('#roles_tag_' + id);
		if (element.length > 0)
		{
			element.toggleClass('pwic_hidden');				// Hide until the request is completed
			fetch('/api/user/roles/set', {	method: 'POST',
											body: new URLSearchParams({	project: project,
																		name: user,
																		role: role}),
											credentials: 'same-origin' })
				.then(response => {
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					response.text().then(text => {
						setTimeout(() => {
							if (element.attr('type') == 'checkbox')
								element.prop('checked', text == 'X');
							if (text != 'OK')
								element.toggleClass('pwic_hidden');
						}, 2000);
					});
				})
				.catch(error => setTimeout(() => element.toggleClass('pwic_hidden'), 2000));
		}
		return false;	// The element is updated async later
	}

	function roles_delete(text, id, project, user) {
		return confirm(text) && roles_toggle(id, project, user, 'delete');
	}
</script>

<script>
	'use strict';

	$('#create_kb').on('change', event => {
		var state = $(event.target).prop('checked');
		$('#create_page').toggleClass('pwic_hidden', state);
		if (state)
			$('#create_page').val('');
	});

	function create_submit() {
		var	project = $('#create_project').val().trim().toLowerCase(),
			kbmode = $('#create_kb').prop('checked'),
			page = $('#create_page').val().trim().toLowerCase();

		// Check the parameters
		if (	!pwic_is_safe(project)
			||	!pwic_is_safe(page)
			||	(['', 'api', 'special'].indexOf(project) !== -1)
			||	(!kbmode && ((['', 'special'].indexOf(page) !== -1) || page.match(/^kb[0-9]{6}$/i)))
		) {
			alert({% trans %}'The parameters are not acceptable.'{% endtrans %});
			return false;
		}

		// Submit the form
		$('INPUT[type=button]').attr('disabled', '');
		var args = {project:		project,
					kb:				kbmode,
					page:			page,
					tags:			$('#create_tags').val(),
					milestone:		$('#create_milestone').val(),
					ref_project:	$('#create_ref_project').val(),
					ref_page:		$('#create_ref_page').val(),
					ref_tags:		$('#create_ref_tags').val()};
		fetch('/api/page/create', {	method: 'POST',
									headers: {'Content-Type': 'application/x-www-form-urlencoded'},
									body: new URLSearchParams(args),
									credentials: 'same-origin'})
			.then(response => {
				$('INPUT[type=button]').removeAttr('disabled');
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				response.json().then(data => window.location = data['url'] + '?success');
			})
			.catch(error => {
				alert(error);
				$('INPUT[type=button]').removeAttr('disabled');
			});
	}
</script>

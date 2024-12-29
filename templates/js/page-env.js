<script>
	'use strict';

	// Easy copy of the global value
	$('INPUT[type=text]').on('dblclick', event => {
		if ($(event.target).val() == '') {
			$(event.target).val($(event.target).prop('placeholder'));
			$(event.target).trigger('keyup');
		}
	});

	// Manage the visibility of the save button
	$('INPUT[type=button]').addClass('pwic_hidden');
	$('INPUT[type=text]').on('keyup', event => {
		// Inbound values
		var value = $(event.target).val(),
			saved = ($(event.target).data('saved') || ''),
			global = ($(event.target).data('global') == 'X');
		// Conditions to show it
		var b1 = !global && (value != saved),
			b2 = global && (value != '');
		$('INPUT[type=button][data-key='+$(event.target).data('key')+']').toggleClass('pwic_hidden', !b1 && !b2);
	});

	// Manage the save button
	$('INPUT[type=button]').on('click', event => {
		var key = $(event.target).data('key'),
			value = $('INPUT[type=text][data-key='+key+']').val();
		env_set(key, value);
	});

	// Load the default values of the configuration
	$('INPUT[type=text]').attr('readonly', '').addClass('pwic_disabled_bg');
	fetch('/api/server/env/get', {	method: 'POST',
									headers: {'Content-Type': 'application/x-www-form-urlencoded'},
									body: new URLSearchParams({project: '{{pwic.project}}'}),
									credentials: 'same-origin'})
		.then(response => {
			if (!response.ok)
				throw Error(response.status + ' ' + response.statusText);
			response.json().then(data => {
				var key, item, element;
				for (key in data) {
					item = data[key];
					element = $('INPUT[type=text][data-key='+key+']');
					if (element.length == 1) {
						element.data('saved', item['value'])
							   .data('global', (item['global'] ? 'X' : ''));
						if (item['global'])
							element.attr('placeholder', item['value']);
						else
							element.val(item['value']);
					}
				}
				$('INPUT[type=text]').removeAttr('readonly').removeClass('pwic_disabled_bg');
			});
		})
		.catch(error => alert(error));

	// Action when the save button is pressed
	function env_set(key, value) {
		fetch('/api/project/env/set', {	method: 'POST',
										headers: {'Content-Type': 'application/x-www-form-urlencoded'},
										body: new URLSearchParams({	project: '{{pwic.project}}',
																	key: key,
																	value: value}),
										credentials: 'same-origin'})
			.then(response => {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				$('INPUT[type=text][data-key='+key+']').data('saved', value);
				$('INPUT[type=button][data-key='+key+']').addClass('pwic_hidden');
			})
			.catch(error => alert(error));
	}
</script>

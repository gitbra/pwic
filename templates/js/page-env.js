<script>
	'use strict';

	// Easy copy of the global value
	$('INPUT[type=text]').on('dblclick', function() {
		if ($(this).val() == '') {
			$(this).val($(this).prop('placeholder'));
			$(this).trigger('keyup');
		}
	});

	// Manage the visibility of the save button
	$('INPUT[type=button]').addClass('pwic_hidden');
	$('INPUT[type=text]').on('keyup', function() {
		// Inbound values
		var value = $(this).val(),
			saved = ($(this).data('saved') || ''),
			global = ($(this).data('global') == 'X');
		// Conditions to show it
		var b1 = !global && (value != saved),
			b2 = global && (value != '');
		$('INPUT[type=button][data-key='+$(this).data('key')+']').toggleClass('pwic_hidden', !b1 && !b2);
	});

	// Manage the save button
	$('INPUT[type=button]').on('click', function() {
		var key = $(this).data('key'),
			value = $('INPUT[type=text][data-key='+key+']').val();
		env_set(key, value);
	});

	// Load the default values of the configuration
	$('INPUT[type=text]').attr('readonly', '').addClass('pwic_disabled_bg');
	fetch('/api/server/env/get', {	method: 'POST',
									headers: {'Content-Type': 'application/x-www-form-urlencoded'},
									body: 'project={{pwic.project|urlencode}}',
									credentials: 'same-origin' })
		.then(function(response) {
			if (!response.ok)
				throw Error(response.status + ' ' + response.statusText);
			else
				response.json().then(function(data) {
					var key, item, element;
					for (key in data)
					{
						item = data[key];
						element = $('INPUT[type=text][data-key='+key+']');
						if (element.length == 1)
						{
							console.assert(item['changeable'] == true);
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
										body:	'project={{pwic.project|urlencode}}' +
												'&key='+encodeURIComponent(key) +
												'&value='+encodeURIComponent(value),
										credentials: 'same-origin' })
			.then(response => {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				$('INPUT[type=text][data-key='+key+']').data('saved', value);
				$('INPUT[type=button][data-key='+key+']').addClass('pwic_hidden');
			})
			.catch(error => alert(error));
	}
</script>

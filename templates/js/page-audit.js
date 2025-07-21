<script>
	'use strict';

	fetch('/api/server/env/get',
			{	method: 'POST',
				headers: {'Content-Type': 'application/x-www-form-urlencoded'},
				body: new URLSearchParams({'project': '{{pwic.project|slash}}'}),
				credentials: 'same-origin'})
		.then(response => {
			if (response.ok)
				response.json().then(data => {
					var key, buffer, tr;
					for (key in data) {
						tr = $(document.createElement('TR')).appendTo($('#audit_envs'));
						$(document.createElement('TD'))
							.html('<code>' + pwic_entities(key) + '</code>')
							.appendTo(tr);
						$(document.createElement('TD'))
							.html(data[key].global
								? '<span title="{% trans %}Global{% endtrans %}">{{pwic.emojis.globe}}</span>'
								: '<span title="{% trans %}Project-dependent{% endtrans %}">{{pwic.emojis.hammer}}</span>')
							.appendTo(tr);
						$(document.createElement('TD'))
							.addClass('pwic_monospace')
							.html(pwic_entities(data[key].value))
							.appendTo(tr);
					}
				});
		});
</script>

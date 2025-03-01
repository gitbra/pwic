<script>
	'use strict';

	{% if pwic.env.no_text_selection %}
		$(document).on('keydown', e => !((e.key == 'F12') || (e.ctrlKey && e.shiftKey && (e.key == 'I')) || (e.ctrlKey && (e.key == 'u'))));
		$(document).on('selectstart', () => false);
		$(document).on('contextmenu', () => false);
		$('ARTICLE *').css(atob('dXNlci1zZWxlY3Q='), 'none');
	{% endif %}

	window.onscroll = () => {
		var	scroll = document.body.scrollTop || document.documentElement.scrollTop,
			height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
		$('#pwic_progress')[0].style.width = ((scroll / height) * 100).toString() + 'vw';
		$('#page_topofpage').toggleClass('pwic_hidden', scroll == 0);
	};

	$(document).on('keyup', event => {
		if (!$('#pwic_browser').hasClass('pwic_hidden'))
			if ((event || window.event).key == 'Escape')
				$('#pwic_browser_access').trigger('click');
	});

	function page_email() {
		{% if pwic.draft %}
			if (confirm({% trans %}'Warning: the current page is a draft, so its content may disappear in the future without notice.'{% endtrans %}))
		{% endif %}
		{
			var url = window.location.toString();
			if (url.endsWith('#'))
				url = url.substring(0, url.length - 1);
			window.location = "mailto:?subject={{pwic.title|urlencode}}&body="+encodeURIComponent('\n\n'+url);
		}
		return false;
	}

	function page_print() {
		window.print();
		return false;
	}

	function page_tmap() {
		var element = $('#pwic_browser');
		element.toggleClass('pwic_hidden');
		if (!element.hasClass('pwic_hidden'))
			element[0].focus();
	}

	function page_post_action(action, confirmText) {
		if (confirm(confirmText)) {
			fetch('/api/page/'+action, {method: 'POST',
										headers: {'Content-Type': 'application/x-www-form-urlencoded'},
										body: new URLSearchParams({	project: '{{pwic.project}}',
																	page: '{{pwic.page}}',
																	revision: {{pwic.revision}}}),
										credentials: 'same-origin'})
				.then(response => {
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					window.location =	'/{{pwic.project|urlencode}}' +
										'/{{pwic.page|urlencode}}' +
										(action != 'delete' ? '/rev{{pwic.revision|urlencode}}' : '') +
										(action == 'delete' ? '?success' : '');
				})
				.catch(error => alert(error));
		}
		return false;
	}

	function page_export(format) {
		fetch('/api/page/export', {	method: 'POST',
									headers: {'Content-Type': 'application/x-www-form-urlencoded'},
									body: new URLSearchParams({	project: '{{pwic.project}}',
																page: '{{pwic.page}}',
																revision: {{pwic.revision}},
																format: format}),
									credentials: 'same-origin'})
			.then(response => {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				var filename = response.headers.get('Content-Disposition').split('"')[1];
				filename = filename.substring(10,filename.length-2);
				filename = decodeURIComponent(escape(atob(filename)))
				response.blob().then(blob => {
					var dl = $(document.createElement('a'))
								.addClass('pwic_hidden')
								.attr('href', window.URL.createObjectURL(new Blob([blob], {type: blob.type})))
								.attr('download', filename)
								.appendTo('body')
								.trigger('click')
								.remove();
					window.URL.revokeObjectURL(dl.href);
					return true;
				});
			})
			.catch(error => alert(error));
		return false;
	}

	{% if not pwic.env.no_copy_code %}
		function page_copy_code() {
			var code = $(this).parent().text().substring($(this).text().length);
			navigator.clipboard.writeText(code).then(
				() => alert({% trans %}'The code has been copied successfully to the clipboard.'{% endtrans %}),
				() => alert({% trans %}'The code cannot be copied to the clipboard.'{% endtrans %})
			);
		}

		$('CODE').each((i, e) => {
			if ((e.clientHeight >= 100) || (e.clientWidth >= 300))
				$(e).prepend($(document.createElement('SPAN'))
								.addClass('pwic_copy_code' + (e.clientHeight <= 50 ? '_tiny' : ''))
								.attr('title', 'Copy')
								.html('{{pwic.emojis.notes}}')
								.on('click', page_copy_code));
		});
	{% endif %}

	{% if not pwic.env.no_table_csv %}
		function page_export_table() {
			var csv, row, x, y, val,
				table = this.parentElement;

			// Prepare the table
			csv = [];
			for (y=0; y<table.rows.length; y++) {
				row = [];
				for (x=0; x<table.rows[y].cells.length; x++) {
					val = table.rows[y].cells[x].textContent;
					if ((val.indexOf('"') != -1) || (val.indexOf(';') != -1))
						val = '"' + val.replaceAll('"', '""') + '"';
					row.push(val);
				}
				csv.push(row.join(';'));
			}

			// Download the file
			var blob = window.URL.createObjectURL(new Blob([csv], {type: 'text/csv'}));
			$(document.createElement('a'))
				.addClass('pwic_hidden')
				.attr('href', blob)
				.attr('download', 'table.csv')
				.appendTo('BODY')
				.trigger('click')
				.remove();
			window.URL.revokeObjectURL(blob);
		}

		$('ARTICLE > TABLE').each((i, e) => {
			if (e.rows.length >= 10)
				$(e).append($(document.createElement('CAPTION'))
								.html('<span class="pwic_desktop">' + {% trans %}'Download this table as CSV file'{% endtrans %} + '<\/span><span class="pwic_mobile">&#x1F4BE;&nbsp;CSV<\/span>')
								.on('click', page_export_table));
		});
	{% endif %}
</script>

<script>
	(function() {
		var	list_initial = null,
			timeout = null;

		$('#page_progress_tags > A:nth-child(1)').on('click', event => {
			$('#page_progress_tags > A:nth-child(n+4)').addClass('pwic_selected');
			clearTimeout(timeout);
			page_progress_refresh();
			return false;
		});

		$('#page_progress_tags > A:nth-child(2)').on('click', event => {
			$('#page_progress_tags > A:nth-child(n+4)').removeClass('pwic_selected');
			clearTimeout(timeout);
			page_progress_refresh();
			return false;
		});

		$('#page_progress_tags > A:nth-child(n+3)').on('click', event => {
			$(event.target).toggleClass('pwic_selected');
			clearTimeout(timeout);
			timeout = setTimeout(page_progress_refresh, 2000);
			return false;
		});

		async function page_progress_refresh() {
			function _pc(a, b) {
				return (b == 0 ? '' : Math.floor(100 * a / b) + ' %');
			}
			function _sl(terms, text, entries) {
				if ({% if pwic.env.no_search %} true {% else %} false {% endif %} || (entries == 0))
					return encodeURIComponent(text);
				return '<a href="/{{pwic.project|urlencode}}/special/search?q=%23'+encodeURIComponent(terms)+'" target="_blank">'+encodeURIComponent(text)+'<\/a>';
			}

			// Get the selected tags
			var tags = '';
			$('#page_progress_tags > A:nth-child(n+4)').each((i, e) => {
				if ($(e).hasClass('pwic_selected'))
					tags += ' ' + $(e).text().substring(1);
			});
			tags = tags.trim();

			// Calculate the progress
			var buffer = '';
			if (tags.length > 0) {
				var args = {project: '{{pwic.project|slash}}',
							tags: tags,
							combined: $('#page_progress_tags > A:nth-child(3)').hasClass('pwic_selected') ? 'on' : ''},
					options = {	method: 'POST',
								headers: {'Content-Type': 'application/x-www-form-urlencoded'},
								body: new URLSearchParams(args),
								credentials: 'same-origin'};
				try {
					var request = await fetch('/api/project/progress/get', options);
					if (request.ok) {
						var data = await request.json();
						for (var tag in data) {
							var item = data[tag];
							if (item['total'] > 0)
								buffer += '<tr>'
											+ '<td>'						+ _sl(tag, tag, 1) + '<\/td>'
											+ '<td>'						+ _sl(tag + ' :draft', item['draft'], item['draft']) + '<\/td>'
											+ '<td class="pwic_desktop">'	+ _pc(item['draft'], item['total']) + '<\/td>'
											+ '<td>'						+ _sl(tag + ' -:draft -:final -:validated', item['step'], item['step']) + '<\/td>'
											+ '<td class="pwic_desktop">'	+ _pc(item['step'], item['total']) + '<\/td>'
											+ '<td>'						+ _sl(tag + ' :final', item['final'], item['final']) + '<\/td>'
											+ '<td class="pwic_desktop">'	+ _pc(item['final'], item['total']) + '<\/td>'
											+ '<td>'						+ _sl(tag + ' :validated', item['validated'], item['validated']) + '<\/td>'
											+ '<td class="pwic_desktop">'	+ _pc(item['validated'], item['total']) + '<\/td>'
										+ '<\/tr>';
						}
					}
				}
				catch (error) {
					console.log(error);
				}
			}

			// Display the result
			var e = $('#page_progress_list');
			e.html((list_initial = list_initial || e.html()) + buffer).toggleClass('pwic_hidden', buffer.length == 0);
		}
	}());
</script>

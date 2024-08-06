<script>
	'use strict';

	function page_start_search() {
		var args = {q: $('#page_search').val()};
		if (args['q'].length > 0) {
			if ($('#page_search_withrev').prop('checked'))
				args['rev'] = 'on';
			if ($('#page_search_casesensitive').prop('checked'))
				args['cs'] = 'on';
			window.location = '/{{pwic.project|urlencode}}/special/search?' + (new URLSearchParams(args).toString());
		}
	}

	function page_search(event) {
		event = event || window.event;
		if (event.key == 'Enter')
			page_start_search();
	}
</script>

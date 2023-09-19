<script>
	'use strict';

	function page_start_search() {
		var q = $('#page_search').val();
		if (q.length > 0)
			window.location = '/{{pwic.project|urlencode}}/special/search?q='+encodeURIComponent(q)
																		+($('#page_search_withrev').prop('checked') ? '&rev=on' : '')
																		+($('#page_search_casesensitive').prop('checked') ? '&cs=on' : '');
	}

	function page_search(event) {
		event = event || window.event;
		if (event.key == 'Enter')
			page_start_search();
	}
</script>

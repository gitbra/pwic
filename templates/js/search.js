<script>
	'use strict';

	function page_start_search() {
		var q = $('#page_search').val(),
			wo = $('#page_search_withrev').prop('checked') ? '&rev=on' : '';
		if (q.length > 0)
			window.location = '/{{pwic.project|urlencode}}/special/search?q='+encodeURIComponent(q)+wo;
	}

	function page_search(event) {
		event = event || window.event;
		if (event.key == 'Enter')
			page_start_search();
	}
</script>

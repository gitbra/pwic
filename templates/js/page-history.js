<script>
	'use strict';

	function history_compare() {
		var rev = [];
		$('input').each((i, e) => {
			e = $(e);
			if ((e.attr('type') == 'checkbox') && e.prop('checked'))
				rev.push(e.data('revision'));
		});
		if (rev.length > 2)
			return false;
		if (rev.length == 2) {
			rev.sort();
			window.location = '/{{pwic.project|escape}}/{{pwic.page|escape}}/rev'+rev[1]+'/compare/rev'+rev[0];
		}
		return true;
	}
</script>

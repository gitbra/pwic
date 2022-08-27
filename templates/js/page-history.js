<script>
	'use strict';

	function history_compare() {
		var rev = [];
		$('input').each(function(index, element) {
			element = $(element);
			if ((element.attr('type') == 'checkbox') && element.prop('checked'))
				rev.push(element.data('revision'));
		});
		if (rev.length > 2)
			return false;
		else
			if (rev.length == 2)
			{
				rev.sort();
				window.location = '/{{pwic.project|escape}}/{{pwic.page|escape}}/rev'+rev[1]+'/compare/rev'+rev[0];
			}
		return true;
	}
</script>

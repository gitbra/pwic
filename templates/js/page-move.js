<script>
	'use strict';

	$('#move_dst_page').on('dblclick', event => {
		if ($(event.target).val() == '')
			$(event.target).val($(event.target).prop('placeholder'));
	});

	function move_submit() {
		// Fetch the parameters
		var srcproj = $('#move_src_project').val(),
			srcpage = $('#move_src_page').val(),
			dstproj = $('#move_dst_project').val(),
			dstpage = $('#move_dst_page').val().trim().toLowerCase();

		// Check the parameters
		if (dstpage == '')
			dstpage = srcpage;
		if (	!pwic_is_safe(srcproj)
			||	!pwic_is_safe(srcpage)
			||	!pwic_is_safe(dstproj)
			||	!pwic_is_safe(dstpage)
			||	((srcproj == dstproj) && (dstpage == srcpage))
			||	((srcproj != dstproj) && (dstpage == ''))
		) {
			alert({% trans %}'The parameters are not acceptable.'{% endtrans %});
			return false;
		}

		// Submit the form
		$('INPUT[type=button]').attr('disabled', '');
		var args = {project: dstproj,
					page: dstpage,
					ref_project: srcproj,
					ref_page: srcpage,
					ignore_file_errors: 'X'};
		fetch('/api/page/move', {	method: 'POST',
									headers: {'Content-Type': 'application/x-www-form-urlencoded'},
									body: new URLSearchParams(args),
									credentials: 'same-origin' })
			.then(response => {
				$('INPUT[type=button]').removeAttr('disabled');
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				window.location = response.url;
			})
			.catch(error => {
				alert(error);
				$('INPUT[type=button]').removeAttr('disabled');
			});
	}
</script>

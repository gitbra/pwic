<script>
	'use strict';

	// -------------------------------- Toolbar

	function edit_decorate(tagStart, tagEnd) {
		var nosel = !md_editor.somethingSelected();
		md_editor.replaceSelection(tagStart + md_editor.getSelection() + tagEnd);
		if (nosel) {
			var cur = md_editor.getCursor();
			md_editor.setCursor(cur.line, cur.ch - tagEnd.length);
		}
		md_editor.focus();
	}

	function edit_decorate_end(text) {
		md_editor.replaceSelection(md_editor.getSelection() + text);
		md_editor.focus();
	}

	function edit_link() {
		if (md_editor.somethingSelected()) {
			// Check the current selection for an autolink
			var	txt = md_editor.getSelection();
			if (txt.match('^[a-z]{3,7}:\/\/')) {
				md_editor.replaceSelection('<' + md_editor.getSelection().replaceAll(' ', '%20') + '>');
				md_editor.focus();
				return;
			}

			// Ask for the link
			var url = prompt({% trans %}'Paste the link:'{% endtrans %}, '');
			if ((url != null) && (url != '')) {
				url = url.trim();
				if ((url.length > 0)
				 && (url.indexOf(':') === -1)
				 && (url.indexOf('/') === -1)
				 && (url == url.toLowerCase()))
					url = '/{{pwic.project}}/' + url;

				// Replace the text by another one
				md_editor.replaceSelection('[' + txt + '](' + url + ')');
			}
		}
		md_editor.focus();
	}

	function _edit_prepend_generic(ftag) {
		// Fit the selection
		var lft = md_editor.getCursor('start'),
			rgt = md_editor.getCursor('end');
		md_editor.setCursor(lft.line, 0);
		md_editor.setSelection(md_editor.getCursor('start'), rgt);

		// Adapt the content to the new format
		var txt = ftag() + md_editor.getSelection();
		md_editor.replaceSelection(txt.split('').map(c => c == '\n' ? '\n' + ftag() : c).join(''));
		md_editor.focus();
	}

	function edit_prepend(tag) {
		return _edit_prepend_generic(() => tag);
	}

	function edit_prepend_nlist() {
		var id = 0;
		return _edit_prepend_generic(() => ++id + '. ');
	}

	function _edit_block_transform(f) {
		if (md_editor.somethingSelected())
			md_editor.replaceSelection(f(md_editor.getSelection()), 'around');
		md_editor.focus();
	}

	function edit_switch_case() {
		_edit_block_transform(s => (s == s.toUpperCase()
										? s.toLowerCase()
										: (s == s.toLowerCase()
												? s.substring(0,1).toUpperCase() + s.substring(1).toLowerCase()
												: s.toUpperCase())));
	}

	function edit_double_spaces() {
		_edit_block_transform(s => s.replace(/  +/g, ' '));
	}

	function edit_left_line() {
		_edit_block_transform(s => s.replaceAll('\r', '').replace(/\n\s+/g, '\n'));
	}

	function edit_no_blank_line() {
		_edit_block_transform(s => s.replaceAll('\r', '').replaceAll(/\n\s*\n/g, '\n'));
	}

	function edit_single_line() {
		_edit_block_transform(s => s.replaceAll('\r', '').replace(/[\s\t]*\n[\s\t]*/, '\n').replaceAll('\n', ' '));
	}

	function edit_table() {
		// Get the dimensions of the table
		var ncol = parseInt(prompt({% trans %}'Number of columns:'{% endtrans %}, 0));
		if (isNaN(ncol) || (ncol < 1))
			return false;
		var nrow = parseInt(prompt({% trans %}'Number of rows:'{% endtrans %}, 0)) + 1;
		if (isNaN(nrow) || (nrow < 1))
			return false;

		// Prepare the associated markdown
		var i, j, buffer = '';
		for (i=0 ; i<nrow ; i++) {
			buffer += '|';
			for (j=0 ; j<ncol ; j++)
				buffer += '          |';
			buffer += '\n';
			if (i == 0) {
				buffer += '|';
				for (j=0 ; j<ncol ; j++)
					buffer += ' -------- |';
				buffer += '\n';
			}
		}

		// Apply the text
		md_editor.replaceSelection(buffer);
		md_editor.focus();
	}

	function edit_table_import() {
		try {
			navigator.clipboard.readText()
				.then(input_text => {
					var i, j, lines, cols,
						ncols = 0,
						nlens = [],
						txt, buffer, nice;

					// Check
					input_text = input_text.replaceAll('\r', '').trim();
					if (input_text.length == 0) {
						$('#edit_toolbar_table').trigger('click');
						return;
					}

					// Scan the dimensions of the table
					lines = input_text.split('\n');
					for (i=0 ; i<lines.length ; i++) {
						cols = lines[i].split('\t');
						ncols = Math.max(ncols, cols.length);
						for (j=0 ; j<cols.length ; j++) {
							if (nlens.length <= j)
								nlens.push(0);
							nlens[j] = Math.max(nlens[j], cols[j].trim().length);
						}
					}
					nice = (nlens.reduce((a, b) => a + b, 0) <= 128);		// To shorten large tables

					// Build the final text
					buffer = '';
					for (i=0 ; i<lines.length ; i++) {
						buffer += '\n';
						cols = lines[i].split('\t');
						for (j=0 ; j<ncols ; j++) {
							txt = (j < cols.length ? cols[j] : '').trim();
							buffer += '| ' + txt + ' '.repeat((nice ? nlens[j] - txt.length : 0) + 1);
						}
						buffer += '|';

						// Header line
						if (i == 0) {
							buffer += '\n';
							for (j=0 ; j<ncols ; j++)
								buffer += '|' + '-'.repeat((nice ? nlens[j] : 1) + 2);
							buffer += '|';
						}
					}

					// Paste the table
					edit_decorate_end('\n' + buffer + '\n\n');
				});
		} catch (e) {
			// See dom.events.testing.asyncClipboard in Firefox
			alert({% trans %}'You cannot use this feature.'{% endtrans %});
		}
	}

	function edit_footnote() {
		// Search for the highest current footnote
		var	id = 0,
			list = [...md_editor.getValue().matchAll(/\[\^([0-9]+)\]/g)];
		list.forEach(match => {
			var value = parseInt(match[1]);
			if (value > id)
				id = value;
		});

		// Apply the footnote
		md_editor.replaceSelection(md_editor.getSelection() + ' [^'+(id+1)+']');
		md_editor.setValue(md_editor.getValue() + '\n\n' + '[^'+(id+1)+']: ');
		md_editor.focus();
		md_editor.setCursor(md_editor.lineCount(), 0);
	}

	function edit_join_document(id, filename, mime) {
		var buffer = '';

		// Include an image
		if (mime.substring(0, 6) == 'image/') {
			var tip = prompt({% trans %}'Tooltip of the image:'{% endtrans %}, ''),
				alt = prompt({% trans %}'Alternate text for the image:'{% endtrans %}, '');
			buffer = '![';
			if (alt != '')
				buffer += pwic_kick(alt, '["]');
			buffer += '](/special/document/' + id;
			if (tip != '')
				buffer += ' "'+pwic_kick(tip, '"')+'"';
			buffer += ')';
		}

		// Any other file
		else
			buffer = '['+filename+'](/special/document/'+id+'?attachment)'

		// Set the value
		md_editor.replaceSelection(buffer);
		md_editor.focus();
	}

	function _edit_convert(endpoint, payload) {
		fetch(endpoint, {	method: 'POST',
							headers: {'Content-Type': 'application/x-www-form-urlencoded'},
							body: new URLSearchParams(payload),
							credentials: 'same-origin'})
			.then(response => {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				response.text().then(text => {
					if ((text != '') && confirm({% trans %}'Do you want to replace the current content by the one of the selected document?'{% endtrans %})) {
						md_editor.setValue(text);
						md_editor.focus();
					}
				});
			})
			.catch(error => alert(error));
	}

	function edit_convert_document(id) {
		_edit_convert('/api/document/convert', {id: id});
	}

	{% if pwic.env.remote_url %}
		function edit_convert_remote_document() {
			var url = prompt({% trans %}'Remote URL to fetch:'{% endtrans %}, '');
			if ((url != null) && (url != ''))
				_edit_convert(	'/api/document/remote/convert',
								{project: '{{pwic.project}}', url: url});
		}
	{% endif %}


	// -------------------------------- File drop

	function edit_refresh_documents() {
		fetch('/api/document/list', {	method: 'POST',
										headers: {'Content-Type': 'application/x-www-form-urlencoded'},
										body: new URLSearchParams({	project: '{{pwic.project}}',
																	page: '{{pwic.page}}' }),
										credentials: 'same-origin'})
			.then(response => {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				response.json().then(data => {
					var i, doc, buffer = '';
					for (i=0 ; i<data.length ; i++) {
						doc = data[i];
						buffer += '<tr>\
										<td>\
											<input type="button" value="{{pwic.emojis.plus}}" title="{% trans %}Add a link{% endtrans %}" onclick="edit_join_document('+doc['id']+', \''+pwic_slash(doc['filename'])+'\', \''+pwic_slash(doc['mime'])+'\')" \/>' +
											(doc['convertible'] ? ' <input class="pwic_desktop" type="button" value="{{pwic.emojis.hammer}}" title="{% trans %}Import the content of the document{% endtrans %}" onclick="edit_convert_document('+doc['id']+')" \/>' : '') +
										'<\/td>\
										<td><a href="/special/document/'+encodeURIComponent(doc['id'])+'/'+encodeURIComponent(doc['filename'])+'" target="_blank">'+pwic_entities(doc['filename'])+'<\/a>'+(doc['exturl']!=''?' {{pwic.emojis.cloud}}':'')+'<\/td>\
										<td class="pwic_desktop">'+(doc['used']?' {{pwic.emojis.green_check}}':'')+'<\/td>\
										<td title="{% trans %}Hash:{% endtrans %} '+pwic_entities(doc['hash'])+'">'+pwic_entities(doc['size'])+'<\/td>\
										<td class="pwic_desktop" title="'+pwic_entities(doc['mime'])+'">'+doc['mime_icon']+' '+pwic_entities(doc['extension'].toUpperCase())+'<\/td>\
										<td class="pwic_desktop"><a href="/special/user/'+encodeURIComponent(doc['author'])+'" target="_blank" rel="nofollow">'+pwic_entities(doc['author'])+'<\/a><\/td>\
										<td>'+pwic_entities(doc['date'])+'<\/td>\
										<td class="pwic_desktop">'+pwic_entities(doc['time'])+'<\/td>\
										<td>\
											<input type="button" value="{{pwic.emojis.curved_left_arrow}}{{pwic.emojis.zwj}}" title="{% trans %}Rename the document{% endtrans %}" onclick="edit_rename_document('+doc['id']+', \''+pwic_slash(doc['filename'])+'\')" \/>\
											<input type="button" onclick="return edit_delete_document('+doc['id']+', \''+pwic_slash(doc['filename'])+'\')" value="{{pwic.emojis.red_check}}" title="{% trans %}Delete the document{% endtrans %}" />\
										<\/td>\
									<\/tr>';
					}
					$('#edit_files_list').html(edit_files_list_initial + buffer).toggleClass('pwic_hidden', data.length == 0);
				});
			})
			.catch(error => alert(error));
	}

	var edit_files_list_initial = $('#edit_files_list').html();
	edit_refresh_documents();	// For the initialization

	function _edit_transfer_files(files) {
		// Create an XHR for each file
		var notification = null;
		for (var i=0 ; i<files.length ; i++) {
			// Fields
			var form = new FormData();
			form.append('project', '{{pwic.project}}');
			form.append('page', '{{pwic.page}}');
			form.append('content', files[i]);

			// Request
			fetch('/api/document/create', {	method: 'POST',
											body: form,
											credentials: 'same-origin'})
				.then(response => {
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					if (notification != null)
						clearTimeout(notification);
					notification = setTimeout(() => {
										edit_refresh_documents();
										alert({% trans %}'The file is uploaded and usable in the list below.'{% endtrans %});
									}, 2000);
				})
				.catch(error => alert(error));
		}
	}

	function edit_upload_document() {
		var obj = $(document.createElement('input'))
						.attr('type', 'file')
						.addClass('pwic_hidden')
						.appendTo('body')
						.on('change', e => { _edit_transfer_files(e.target.files), obj.remove() })
						.on('cancel', () => obj.remove())
						.trigger('click');
	}

	function edit_drop(event) {
		$('#edit_files_drop').removeClass('pwic_dragover');
		if (event.dataTransfer.items) {
			event.preventDefault();
			event.stopPropagation();
			_edit_transfer_files(event.dataTransfer.files);
		} else
			alert({% trans %}'Unsupported feature.'{% endtrans %});
	}

	function edit_dragover(event) {
		$('#edit_files_drop').addClass('pwic_dragover');
		event.preventDefault();
		event.stopPropagation();
	}

	function edit_dragleave(event) {
		$('#edit_files_drop').removeClass('pwic_dragover');
		event.preventDefault();
		event.stopPropagation();
	}

	function edit_rename_document(id, filename) {
		var newfn = prompt('Type the new file name:', filename);
		if ((newfn != null) && (newfn != filename)) {
			fetch('/api/document/rename', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body: new URLSearchParams({	id: id,
																		project: '{{pwic.project}}',
																		filename: newfn}),
											credentials: 'same-origin'})
				.then(response => {
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					setTimeout(edit_refresh_documents, 1000);
				})
				.catch(error => alert(error));
		}
		return false;
	}

	function edit_delete_document(id, filename) {
		if (confirm({% trans %}'Are sure to delete "%s"?'{% endtrans %}.replace('%s', filename))) {
			fetch('/api/document/delete', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body: new URLSearchParams({	id: id,
																		project: '{{pwic.project}}'}),
											credentials: 'same-origin'})
				.then(response => {
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					setTimeout(edit_refresh_documents, 1000);
				})
				.catch(error => alert(error));
		}
		return false;
	}


	// -------------------------------- Submit a page

	$('#edit_comment').on('dblclick', event => {
		if ($(event.target).val() == '')
			$(event.target).val($(event.target).prop('placeholder'));
	});

	var edit_submittable = false,
		edit_preview_hwnd = null;

	function edit_submit_form() {
		// Check the current values
		edit_submittable = ($('#edit_title').val() != '')
						&& ($('#edit_comment').val() != '');
		if (!edit_submittable) {
			alert({% trans %}'Some fields are mandatory.'{% endtrans %});
			return false;
		}

		// Disable the button temporarily
		$('#edit_submit').prop('disabled', true);
		setTimeout(() => $('#edit_submit').prop('disabled', false), 5000);

		// First ping-pong the server to make sure that the session is still valid
		fetch('/api/server/ping', {	method: 'POST',
									credentials: 'same-origin'})
			.then(response => {
				var errorPing = {% trans %}'Your session is not valid anymore. Please reconnect from another tab and retry.'{% endtrans %};
				if (!response.ok)
					alert('['+response.status+'] '+errorPing);
				else
					response.text().then(text => {
						if (text != 'OK') {
							alert(errorPing);
							return;
						}

						// Close the preview
						if (edit_preview_hwnd != null) {
							edit_preview_hwnd.close();
							edit_preview_hwnd = null;
						}

						// Query the current revision of the modified page
						fetch('/api/project/get', {	method: 'POST',
													headers: {'Content-Type': 'application/x-www-form-urlencoded'},
													body: new URLSearchParams({	project: '{{pwic.project}}',
																				page: '{{pwic.page}}'}),
													credentials: 'same-origin'})
							.then(response => {
								if (!response.ok)
									throw Error('['+response.status+'] '+response.statusText);
								response.json().then(data => {
									// Check the conflict
									if (data['{{pwic.page}}']['revisions'][0]['revision'] > {{pwic.revision}}) {
										if (!confirm({% trans %}'Warning: the page has been modified in parallel of your current modifications.\n\nConsequently, your changes will be posted as a removable draft. You must merge the changes manually later.'{% endtrans %}))
											return false;
										$('#edit_draft').prop('checked', true);
										$('#edit_final').prop('checked', false);
									}

									// Submit the modifications
									{# sof/7542586 #}
									var form = {project:	'{{pwic.project}}',
												page:		'{{pwic.page}}',
												title:		$('#edit_title').val(),
												tags:		$('#edit_tags').val(),
												markdown:	md_editor.getValue(),
												comment:	$('#edit_comment').val(),
												milestone:	$('#edit_milestone').val(),
												draft:		$('#edit_draft').prop('checked'),
												final:		$('#edit_final').prop('checked'),
												header:		$('#edit_header').prop('checked'),
												protection:	$('#edit_protection').prop('checked')};
									fetch('/api/page/edit', {	method: 'POST',
																headers: {'Content-Type': 'application/x-www-form-urlencoded'},
																body: new URLSearchParams(form),
																credentials: 'same-origin'})
										.then(response => {
											if (!response.ok)
												throw Error(response.status + ' ' + response.statusText);
											window.location = '/{{pwic.project|urlencode}}/{{pwic.page|urlencode}}?success';
										})
										.catch(error => alert(error));
								});
							})
							.catch(error => alert(error));
					});
			})
			.catch(error => alert({% trans %}'The server or your Internet connection is down.'{% endtrans %}));
	}

	function edit_preview_md(pageName) {
		fetch('/api/markdown/convert', {method: 'POST',
										headers: {'Content-Type': 'application/x-www-form-urlencoded'},
										body: new URLSearchParams({	project: '{{pwic.project}}',
																	markdown: md_editor.somethingSelected() ? md_editor.getSelection() : md_editor.getValue()}),
										credentials: 'same-origin'})
			.then(response => {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				response.text().then(text => {
					if (edit_preview_hwnd != null)
						edit_preview_hwnd.close();
					edit_preview_hwnd = window.open('');
					edit_preview_hwnd.document.head.innerHTML = '<link rel="stylesheet" type="text/css" href="'+window.location.protocol+'//'+window.location.host+'/static/styles.css" />';
					edit_preview_hwnd.document.title = {% trans %}'Preview of the page'{% endtrans %} + ' "'+pageName+'"';
					edit_preview_hwnd.document.body.innerHTML = '\
	<article>\
		<p style="position:fixed; top:0px; right:0px; padding:15px">\
			<input type="button" onclick="window.close()" value="{{pwic.emojis.door}} '+{% trans %}'Close the preview'{% endtrans %}+'" />\
		<\/p>\
		'+text+'\
	<\/article>';
					edit_preview_hwnd.window.onkeydown = function(event) {
							if (event.key == 'Escape') {
								edit_preview_hwnd.close();
								edit_preview_hwnd = null;
							}
						};
				});
			})
			.catch(error => alert(error));
	}


	// -------------------------------- Leave without saving

	window.onbeforeunload = function(e) {
		var	e = e || window.event;
		if (!edit_submittable)
			if (e)
				e.returnValue = {% trans %}'The current changes may be lost.'{% endtrans %};
	};


	// -------------------------------- Markdown editor

	function edit_undo(mode) {
		if (mode)
			md_editor.undo();
		else
			md_editor.redo();
		md_editor.focus();
		return false;
	}

	function _edit_get_shortcuts() {		// Callable once
		var sc = {};
		$("INPUT[type='button'][data-shortcut]").each((i, e) => {
			e.title = (e.title || '') + ' (' + e.dataset['shortcut'] + ')';
			sc[e.dataset.shortcut] = cm => e.click();
		});
		return sc;
	}

	var md_editor = CodeMirror.fromTextArea(document.getElementById('edit_markdown'), {
						mode: 'markdown',
						lineNumbers: true,
						lineWrapping: true,
						extraKeys: _edit_get_shortcuts()
					});
</script>

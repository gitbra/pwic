<script>
	'use strict';

	// -------------------------------- Toolbar

	function edit_decorate(tagStart, tagEnd) {
		var	ta = $('#edit_markdown')[0],
			ss = ta.selectionStart,
			se = ta.selectionEnd;

		// Replace the text by another one
		ta.value = ta.value.substring(0, ss) + tagStart + ta.value.substring(ss, se) + tagEnd + ta.value.substring(se);
		ta.selectionStart = ss + tagStart.length;
		ta.selectionEnd = se + tagStart.length;
		ta.focus();
	}

	function edit_decorate_end(text) {
		var	ta = $('#edit_markdown')[0],
			se = ta.selectionEnd;
		ta.value = ta.value.substring(0, se) + text + ta.value.substring(se);
		ta.selectionStart = se + text.length;
		ta.selectionEnd = ta.selectionStart;
		ta.focus();
	}

	function edit_link() {
		var	ta = $('#edit_markdown')[0],
			ss = ta.selectionStart,
			se = ta.selectionEnd;

		// Find the cursors
		if (ss != se)
		{
			// Check the current selection for an autolink
			if (ta.value.substring(ss, se).match('^[a-z]{3,5}:\/\/'))
			{
				edit_decorate('<', '>');
				return;
			}

			// Ask for the link
			var url = prompt({% trans %}'Paste the link:'{% endtrans %}, '');
			if ((url != null) && (url != ''))
			{
				url = url.trim();
				if ((url.length > 0)
				 && (url.indexOf(':') === -1)
				 && (url.indexOf('/') === -1)
				 && (url.indexOf(' ') === -1))
					url = '/{{pwic.project}}/' + url.toLowerCase();

				// Replace the text by another one
				ta.value = ta.value.substring(0, ss) + '[' + ta.value.substring(ss, se) + ']('+url+')' + ta.value.substring(se);
				ta.selectionStart = ss;
				ta.selectionEnd = se + 4 + url.length;
			}
		}
		ta.focus();
	}

	function _edit_prepend_generic(ftag) {
		var	ta   = $('#edit_markdown')[0],
			ss   = ta.selectionStart,
			se   = ta.selectionEnd,
			stag = '';
		if (ss > se)
			ss, se = se, ss
		
		// Move the cursor at the beginning of the line
		while (ta.value[ss] != '\n')
		{
			if (ss > 0)
				ss--;
			else
				break;
		}

		// Prepend
		for (var i=ss; i<=se; )
		{
			if (ta.value[i] != '\n')
			{
				i++;
				continue;
			}
			i++;
			stag = ftag();
			ta.value = ta.value.substring(0, i) + stag + ta.value.substring(i);
			i += stag.length;
			se += stag.length;
		}
		ta.selectionStart = ss;
		ta.selectionEnd = se;
		ta.focus();
	}

	function edit_prepend(tag) {
		return _edit_prepend_generic(() => tag);
	}

	function edit_prepend_nlist() {
		var id = 0;
		return _edit_prepend_generic(() => ++id + '. ');
	}

	function _edit_block_transform(f) {
		// Locate the text
		var	ta = $('#edit_markdown')[0],
			ss = ta.selectionStart,
			se = ta.selectionEnd;
		if (ss > se)
			ss, se = se, ss

		// Transform the text
		var newtxt = f(ta.value.substring(ss, se));
		ta.value = ta.value.substring(0, ss) + newtxt + ta.value.substring(se);
		ta.selectionStart = ss;
		ta.selectionEnd = ss + newtxt.length;
		ta.focus();
	}

	function edit_switch_case() {
		_edit_block_transform(s => (s == s.toUpperCase() ? s.toLowerCase() : s.toUpperCase()));
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
		var i, j, buffer='';
		for (i=0 ; i<nrow ; i++)
		{
			buffer += '|';
			for (j=0 ; j<ncol ; j++)
				buffer += '          |';
			buffer += '\n';
			if (i == 0)
			{
				buffer += '|';
				for (j=0 ; j<ncol ; j++)
					buffer += ' -------- |';
				buffer += '\n';
			}
		}

		// Apply the text
		if (typeof easyMDE !== 'undefined')
		{
			easyMDE.codemirror.replaceSelection(buffer);
			easyMDE.codemirror.focus();
		}
		else
		{
			var	ta = $('#edit_markdown')[0],
				se = ta.selectionEnd;
			ta.value = ta.value.substring(0, se) + buffer + ta.value.substring(se);
			ta.focus();
		}
	}

	function edit_table_import() {
		try {
			navigator.clipboard.readText()
				.then(function(input_text) {
					var i, j, lines, cols,
						ncols = 0,
						nlens = [],
						txt, buffer, nice;

					// Check
					input_text = input_text.replaceAll('\r', '').trim();
					if (input_text.length == 0)
					{
						$('#edit_toolbar_table').trigger('click');
						return;
					}

					// Scan the dimensions of the table
					lines = input_text.split('\n');
					for (i=0 ; i<lines.length ; i++)
					{
						cols = lines[i].split('\t');
						ncols = Math.max(ncols, cols.length);
						for (j=0 ; j<cols.length ; j++)
						{
							if (nlens.length <= j)
								nlens.push(0);
							nlens[j] = Math.max(nlens[j], cols[j].trim().length);
						}
					}
					nice = (nlens.reduce((a, b) => a + b, 0) <= 128);		// To shorten large tables

					// Build the final text
					buffer = '';
					for (i=0 ; i<lines.length ; i++)
					{
						buffer += '\n';
						cols = lines[i].split('\t');
						for (j=0 ; j<ncols ; j++)
						{
							txt = (j < cols.length ? cols[j] : '').trim();
							buffer += '| ' + txt + ' '.repeat((nice ? nlens[j] - txt.length : 0) + 1);
						}
						buffer += '|';

						// Header line
						if (i == 0)
						{
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
		var	ta = $('#edit_markdown')[0],
			se = ta.selectionEnd;

		// Search for the highest current footnote
		var	id = 0,
			list = [...ta.value.matchAll(/\[\^([0-9]+)\]/g)];
		list.forEach(function(match){
			var value = parseInt(match[1]);
			if (value > id)
				id = value;
		});

		// Apply the footnote
		ta.value = ta.value.substring(0, se) + ' [^'+(id+1)+']' + ta.value.substring(se) + '\n\n' + '[^'+(id+1)+']: '
		ta.selectionStart = ta.selectionEnd = ta.value.length;
		ta.focus();
	}

	function edit_join_document(id, filename, mime) {
		var buffer = '';

		// Include an image
		if (mime.substring(0, 6) == 'image/')
		{
			var tip = prompt('Tooltip of the image:', ''),
				alt = prompt('Alternate text for the image:', '');
			buffer = '![';
			if (alt != '')
				buffer += pwic_kick(alt, '[]');
			buffer += '](/special/document/' + id;
			if (tip != '')
				buffer += ' "'+pwic_kick(tip, '"')+'"';
			buffer += ')';
		}

		// Any other file
		else
			buffer = '['+filename+'](/special/document/'+id+'?attachment)'

		// Set the value
		if (typeof easyMDE !== 'undefined')
		{
			easyMDE.codemirror.replaceSelection(buffer);
			easyMDE.codemirror.focus();
		}
		else
		{
			var	ta = $('#edit_markdown')[0],
				ss = ta.selectionStart,
				se = ta.selectionEnd;
			ta.value = ta.value.substring(0, ss) + buffer + ta.value.substring(se);
			ta.selectionStart = ss + buffer.length;
			ta.selectionEnd = ta.selectionStart;
			ta.focus();
		}
	}

	function edit_convert_document(id) {
		fetch('/api/document/convert', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body:	'id='+encodeURIComponent(id),
											credentials: 'same-origin' })
			.then(function(response) {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				else
					response.text().then(function(text) {
						if ((text != '') && confirm({% trans %}'Do you want to replace the current content by the one of the selected document?'{% endtrans %}))
						{
							if (typeof easyMDE !== 'undefined')
							{
								easyMDE.value(text);
								easyMDE.codemirror.focus();
							}
							else
							{
								var ta = $('#edit_markdown')[0];
								ta.value = text;
								ta.selectionStart = 0;
								ta.selectionEnd = 0;
								ta.focus();
							}
						}
					});
			})
			.catch(error => alert(error));
	}


	// -------------------------------- Editor

	$('#edit_markdown').on('keydown', function(event) {
		// Pressed key as string
		event = event || window.event;
		var key = '';
		if (event.ctrlKey)
			key += '+Ctrl';
		if (event.altKey)
			key += '+Alt';
		if (event.shiftKey)
			key += '+Shift';
		if ((event.keyCode >= 0x41) && (event.keyCode <= 0x5A))
			key += '+' + event.key.toUpperCase();
		else
			if (([9, 27, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123].indexOf(event.keyCode) !== -1) || (event.key.length == 1))
				key += '+' + event.key.substr(0, 3);
		if (key.length > 1)
			key = key.substr(1);

		// Block alignment
		if (key == 'Tab')
		{
			var	ta = $('#edit_markdown')[0],
				ss = ta.selectionStart,
				se = ta.selectionEnd;
			if (ss == se)
			{
				ta.value = ta.value.substring(0, ss) + "\t" + ta.value.substring(ss);
				ta.selectionStart = ss + 1;
				ta.selectionEnd = ss + 1;
			}
			else
				edit_prepend("\t");
			return false;
		}

		// Automatic shortcuts
		var buts = $("#edit_toolbar INPUT[type='button'][data-shortcut='"+pwic_slash(key)+"']");
		if (buts.length == 1)
		{
			buts.trigger('click');
			event.preventDefault();
			return false
		}
		return true;
	});

	$('[data-shortcut]').each((i, e) => e.title = (e.title || '') + ' (' + e.dataset['shortcut'] + ')');


	// -------------------------------- File drop

	function edit_refresh_documents() {
		fetch('/api/document/list', {	method: 'POST',
										headers: {'Content-Type': 'application/x-www-form-urlencoded'},
										body:	'project={{pwic.project|urlencode}}' +
												'&page={{pwic.page|urlencode}}',
										credentials: 'same-origin' })
			.then(function(response) {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				else
					response.json().then(function(data) {
						var i, doc, buffer = '';
						for (i=0 ; i<data.length ; i++)
						{
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

	function edit_drop(event) {
		$('#edit_files_drop').removeClass('pwic_dragover');
		if (event.dataTransfer.items)
		{
			event.preventDefault();
			event.stopPropagation();
			
			// Create an XHR for each file
			var files = event.dataTransfer.files,
				notification = null;
			for (var i=0 ; i<files.length ; i++)
			{
				// Fields
				var form = new FormData();
				form.append('project', '{{pwic.project|escape}}');
				form.append('page', '{{pwic.page|escape}}');
				form.append('content', files[i]);

				// Request
				fetch('/api/document/create', {	method: 'POST',
												body: form,
												credentials: 'same-origin' })
					.then(function(response) {
						if (!response.ok)
							throw Error(response.status + ' ' + response.statusText);
						else
						{
							if (notification != null)
								clearTimeout(notification);
							notification = setTimeout(function() {
												edit_refresh_documents();
												alert({% trans %}'The file is uploaded and usable in the list below.'{% endtrans %});
											}, 2000);
						}
					})
					.catch(error => alert(error));
			}
		}
		else
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
		if ((newfn != null) && (newfn != filename))
		{
			fetch('/api/document/rename', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body:	'id='+encodeURIComponent(id)+
													'&project={{pwic.project|urlencode}}'+
													'&filename='+encodeURIComponent(newfn),
											credentials: 'same-origin' })
				.then(function(response) {
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					else
						setTimeout(function() {
							edit_refresh_documents();
						}, 1000);
				})
				.catch(error => alert(error));
		}
		return false;
	}

	function edit_delete_document(id, filename) {
		if (confirm({% trans %}'Are sure to delete "%s"?'{% endtrans %}.replace('%s', filename)))
		{
			fetch('/api/document/delete', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body:	'id='+encodeURIComponent(id)+
													'&project={{pwic.project|urlencode}}',
											credentials: 'same-origin' })
				.then(function(response) {
					if (!response.ok)
						throw Error(response.status + ' ' + response.statusText);
					else
						setTimeout(function() {
							edit_refresh_documents();
						}, 1000);
				})
				.catch(error => alert(error));
		}
		return false;
	}


	// -------------------------------- Submit a page

	$('#edit_comment').on('dblclick', function() {
		if ($(this).val() == '')
			$(this).val($(this).prop('placeholder'));
	});

	var edit_submittable = false,
		edit_preview_hwnd = null;

	function edit_submit_form() {
		// Check the current values
		edit_submittable = ($('#edit_title').val() != '')
						&& ($('#edit_comment').val() != '');
		if (!edit_submittable)
		{
			alert({% trans %}'Some fields are mandatory.'{% endtrans %});
			return false;
		}

		// Disable the button temporarily
		$('#edit_submit').prop('disabled', true);
		setTimeout(function() {
				$('#edit_submit').prop('disabled', false);
			}, 5000);

		// First ping-pong the server to make sure that the session is still valid
		fetch('/api/server/ping', {	method: 'POST',
									credentials: 'same-origin' })
			.then(function(response) {
				var errorPing = {% trans %}'Your session is not valid anymore. Please reconnect from another tab and retry.'{% endtrans %};
				if (!response.ok)
					alert('['+response.status+'] '+errorPing);
				else
					response.text().then(function(text) {
						if (text != 'OK')
							alert(errorPing);
						else
						{
							// Close the preview
							if (edit_preview_hwnd != null)
							{
								edit_preview_hwnd.close();
								edit_preview_hwnd = null;
							}

							// Query the current revision of the modified page
							fetch('/api/project/get', {	method: 'POST',
														headers: {'Content-Type': 'application/x-www-form-urlencoded'},
														body:	'project={{pwic.project|urlencode}}'+
																'&page={{pwic.page|urlencode}}',
														credentials: 'same-origin' })
								.then(function(response) {
									if (!response.ok)
										throw Error('['+response.status+'] '+response.statusText);
									response.json().then(function(data) {
										if (data['{{pwic.page|escape}}']['revisions'][0]['revision'] > {{pwic.revision}})
										{
											if (!confirm({% trans %}'Warning: the page has been modified in parallel of your current modifications.\n\nConsequently, your changes will be posted as a removable draft. You must merge the changes manually later.'{% endtrans %}))
												return false;
											$('#edit_draft').prop('checked', true);
											$('#edit_final').prop('checked', false);
										}

										// The modifications can be submitted
										fetch('/api/page/edit', {	method: 'POST',
																	headers: {'Content-Type': 'application/x-www-form-urlencoded'},
																	body:	'project={{pwic.project|urlencode}}'+
																			'&page={{pwic.page|urlencode}}'+
																			'&title='+encodeURIComponent($('#edit_title').val())+
																			'&tags='+encodeURIComponent($('#edit_tags').val())+
																			'&markdown='+encodeURIComponent($('#edit_markdown').val())+
																			'&comment='+encodeURIComponent($('#edit_comment').val())+
																			'&milestone='+encodeURIComponent($('#edit_milestone').val())+
																			'&draft='+encodeURIComponent($('#edit_draft').prop('checked'))+
																			'&final='+encodeURIComponent($('#edit_final').prop('checked'))+
																			'&header='+encodeURIComponent($('#edit_header').prop('checked'))+
																			'&protection='+encodeURIComponent($('#edit_protection').prop('checked')),
																	credentials: 'same-origin' })
											.then(function(response) {
												if (!response.ok)
													throw Error(response.status + ' ' + response.statusText);
												window.location = '/{{pwic.project|urlencode}}/{{pwic.page|urlencode}}?success';
											})
											.catch(error => alert(error));
									});
								})
								.catch(error => alert(error));
						}
					});
			})
			.catch(function(error) {
				alert({% trans %}'The server or your Internet connection is down.'{% endtrans %});
			});
	}

	function edit_preview_md(pageName) {
		var	ta = $('#edit_markdown')[0],
			ss = ta.selectionStart,
			se = ta.selectionEnd;
		fetch('/api/markdown/convert', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body:	'project={{pwic.project|urlencode}}' +
													'&markdown='+encodeURIComponent(ss == se ? ta.value : ta.value.substring(ss, se)),
											credentials: 'same-origin' })
			.then(function(response) {
				if (!response.ok)
					throw Error(response.status + ' ' + response.statusText);
				else
					response.text().then(function(text) {
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
								if (event.key == 'Escape')
								{
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
		var	msg = {% trans %}'The current changes may be lost.'{% endtrans %},
			e = e || window.event;
		if (!edit_submittable)
		{
			if (e)
				e.returnValue = msg;
			return msg;
		}
	};
</script>

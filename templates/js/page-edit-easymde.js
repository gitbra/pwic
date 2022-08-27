<script>
	var easyMDE_buttons = [
			{	name: 'custom',
				action: function(editor) {
					edit_table({% trans %}'Number of columns:'{% endtrans %}, {% trans %}'Number of rows:'{% endtrans %})
				},
				className: 'fa fa-table',
				title: {% trans %}'Insert a table'{% endtrans %},
			},
			{	name: 'custom',
				action: function(editor) {
					alert({% trans %}'From the list of documents, please rather use the sign + in front of the file that you want to attach as an image or as a link.'{% endtrans %});
				},
				className: 'fa fa-paperclip',
				title: {% trans %}'Attach an uploaded document'{% endtrans %},
			},
			{	name: 'custom',
				action: function(editor) {
					if (confirm({% trans %}'Are you sure to switch back to the basic editor?'{% endtrans %}))
					{
						$('#edit_toolbar').removeClass('pwic_hidden');
						easyMDE.toTextArea();
						easyMDE = null;
					}
				},
				className: 'fa fa-edit',
				title: {% trans %}'Switch to the classical editor'{% endtrans %},
			}
		];
	var easyMDE = new EasyMDE({	element: $('#edit_markdown')[0],
								forceSync: true,
								indentWithTabs: false,
								lineWrapping: true,
								promptURLs: true,
								spellChecker: false,
								nativeSpellcheck: true,
								sideBySideFullscreen: false,
								tabSize: 4,
								toolbar: [	'undo', 'redo', '|',
											'bold', 'italic', /* TODO underline, */ 'strikethrough', 'clean-block', '|',
											'heading-smaller', 'heading-bigger', 'horizontal-rule', '|',
											'unordered-list', 'ordered-list', 'link', 'image', easyMDE_buttons[0], easyMDE_buttons[1], '|',
											'quote', 'code', '|',
											'preview', 'fullscreen', easyMDE_buttons[2]
											// guide heading heading-1 heading-2 heading-3 side-by-side table
										],
								status: false
							});
</script>

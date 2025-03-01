<script src="/static/svg-pan-zoom.min.js"></script>
<script>
	'use strict';

	// Get the graph from the API
	var graph_cache = null;

	function graph_get_data(action) {
		// Download from cache
		if ((action == 'download') && (graph_cache != null))
			return graph_download();

		// Else first download
		fetch('/api/project/graph/get', {	method: 'POST',
											headers: {'Content-Type': 'application/x-www-form-urlencoded'},
											body: new URLSearchParams({project: '{{pwic.project}}'}),
											credentials: 'same-origin'})
		.then(response => {
			if (!response.ok)
				throw Error(response.status + ' ' + response.statusText);
			response.text().then(text => {
				graph_cache = text;
				if (action == 'render')
					graph_generate_svg();
				else
					if (action == 'download')
						graph_download();
			});
		})
		.catch(error => alert(error));
	}
	graph_get_data('render');

	// Download the graph as a raw file
	function graph_download() {
		if (graph_cache == null)
			return false;
		var blob = window.URL.createObjectURL(new Blob([graph_cache], {type: 'text/vnd.graphviz'}));
		$(document.createElement('a'))
					.addClass('pwic_hidden')
					.attr('href', blob)
					.attr('download', '{{pwic.project}}.gv')
					.appendTo('BODY')
					.trigger('click')
					.remove();
		window.URL.revokeObjectURL(blob);
		return true;
	}

	// Generate the graph
	function graph_generate_svg() {
		var worker = new Worker('/static/viz.js');
		worker.onmessage = function(e) {
			// Render SVG
			var graph = $('#graph_viz')[0];
			var svg = (new DOMParser()).parseFromString(e.data, 'image/svg+xml').documentElement;
			graph.appendChild(svg);

			// Zooming area for SVG
			var panZoom = svgPanZoom(svg, {zoomEnabled: true, controlIconsEnabled: true, center: true, minZoom: 0.1});
			svg.addEventListener('paneresize', e => panZoom.resize(), false);
			window.addEventListener('resize', e => panZoom.resize());
			worker.terminate();
		};
		worker.onerror = function(e) {
			alert(e.message === undefined ? 'The graph cannot be rendered.' : e.message);
		};
		worker.postMessage({src: graph_cache, options: {engine: 'dot', format: 'svg'}});
	}
</script>

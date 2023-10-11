document.addEventListener('DOMContentLoaded', (ev) => {
	const accordionState = window.localStorage.getItem('accordion-id');

	if (accordionState == null || accordionState == '{}')
		document.querySelectorAll('[data-isopen="false"]')
			.forEach(item => item.setAttribute('data-isopen', 'true'));

	const moduleName = location.pathname.match(/\/module-(.+)\.html$/)?.[1];

	if (moduleName) {
		const modulePrefix = `module:${moduleName}.`;

		document.querySelectorAll(`a[href^="module-${CSS.escape(moduleName)}."]`).forEach(a => {
			if (a.text?.indexOf(modulePrefix) == 0)
				a.text = a.text.substring(modulePrefix.length);
		});
	}

	document.querySelectorAll('.param-type, .type-signature').forEach(span => {
		let replaced;
		do {
			replaced = false;
			span.innerHTML = span.innerHTML.replace(/\b(Object|Array)\.&lt;((?:(?!&[lg]t;).)+)&gt;/,
				(m, t, st) => {
					replaced = true;

					if (t == 'Object')
						return `Object&lt;${st.replace(/,\s*/, ':&#8239;')}&gt;`;
					else
						return `${st}[]`;
				});
		} while (replaced);
	});

	document.querySelectorAll('.type-signature').forEach(span => {
		span.innerHTML = span.innerHTML.replace(/\(nullable\) (.+)$/,
			'$1<span class="signature-attributes">nullable</span>');
	});
});

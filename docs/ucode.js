document.addEventListener('DOMContentLoaded', (ev) => {
	const accordionState = window.localStorage.getItem('accordion-id');

	if (accordionState == null || accordionState == '{}')
		document
			.querySelector('[data-isopen="false"]')
			.setAttribute('data-isopen', 'true');
});

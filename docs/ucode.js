document.addEventListener('DOMContentLoaded', (ev) => {
	const accordionState = window.localStorage.getItem('accordion-id');

	if (accordionState == null || accordionState == '{}')
		document.querySelectorAll('[data-isopen="false"]')
			.forEach(item => item.setAttribute('data-isopen', 'true'));
});

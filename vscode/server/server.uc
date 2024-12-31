import { analyze, TOKEN_TYPES, TOKEN_MODIFIERS } from 'uscope';
import { open, writefile, popen } from 'fs';

let types;
try {
	types = json(open(`${sourcepath(0, true)}/types.json`, 'r'));
}
catch (e) {
	types = {};
}

const KIND_TEXT = 1;
const KIND_METHOD = 2;
const KIND_FUNCTION = 3;
const KIND_CONSTRUCTOR = 4;
const KIND_FIELD = 5;
const KIND_VARIABLE = 6;
const KIND_CLASS = 7;
const KIND_INTERFACE = 8;
const KIND_MODULE = 9;
const KIND_PROPERTY = 10;
const KIND_UNIT = 11;
const KIND_VALUE = 12;
const KIND_ENUM = 13;
const KIND_KEYWORD = 14;
const KIND_SNIPPET = 15;
const KIND_COLOR = 16;
const KIND_FILE = 17;
const KIND_REFERENCE = 18;
const KIND_FOLDER = 19;
const KIND_ENUM_MEMBER = 20;
const KIND_CONSTANT = 21;
const KIND_STRUCT = 22;
const KIND_EVENT = 23;
const KIND_OPERATOR = 24;
const KIND_TYPE_PARAMETER = 25;

const COMPLETION_INVOKED = 1;
const COMPLETION_TRIGGER_CHAR = 2;
const COMPLETION_TRIGGER_INCOMPLETE = 3;

const INSERT_FORMAT_PLAINTEXT = 1;
const INSERT_FORMAT_SNIPPET = 2;

const SEVERITY_ERROR = 1;
const SEVERITY_WARNING = 2;
const SEVERITY_INFORMATION = 3;
const SEVERITY_HINT = 4;

const FIND_PREFER_NEXT = (1 << 0);
const FIND_SKIP_SPACE = (1 << 1);

const TK_LEXP = 1,        TK_REXP = 2,        TK_LSTM = 3,        TK_RSTM = 4,        TK_IF = 5;
const TK_ELSE = 6,        TK_COMMA = 7,       TK_ASSIGN = 8,      TK_ASADD = 9,       TK_ASSUB = 10;
const TK_ASMUL = 11,      TK_ASDIV = 12,      TK_ASMOD = 13,      TK_ASLEFT = 14,     TK_ASRIGHT = 15;
const TK_ASBAND = 16,     TK_ASBXOR = 17,     TK_ASBOR = 18,      TK_QMARK = 19,      TK_COLON = 20;
const TK_OR = 21,         TK_AND = 22,        TK_BOR = 23,        TK_BXOR = 24,       TK_BAND = 25;
const TK_EQS = 26,        TK_NES = 27,        TK_EQ = 28,         TK_NE = 29,         TK_LT = 30;
const TK_LE = 31,         TK_GT = 32,         TK_GE = 33,         TK_IN = 34,         TK_LSHIFT = 35;
const TK_RSHIFT = 36,     TK_ADD = 37,        TK_SUB = 38,        TK_MUL = 39,        TK_DIV = 40;
const TK_MOD = 41,        TK_EXP = 42,        TK_NOT = 43,        TK_COMPL = 44,      TK_INC = 45;
const TK_DEC = 46,        TK_DOT = 47,        TK_LBRACK = 48,     TK_RBRACK = 49,     TK_LPAREN = 50;
const TK_RPAREN = 51,     TK_TEXT = 52,       TK_LBRACE = 53,     TK_RBRACE = 54,     TK_SCOL = 55;
const TK_ENDIF = 56,      TK_ELIF = 57,       TK_WHILE = 58,      TK_ENDWHILE = 59,   TK_FOR = 60;
const TK_ENDFOR = 61,     TK_FUNC = 62,       TK_LABEL = 63,      TK_ENDFUNC = 64,    TK_TRY = 65;
const TK_CATCH = 66,      TK_SWITCH = 67,     TK_CASE = 68,       TK_DEFAULT = 69,    TK_ELLIP = 70;
const TK_RETURN = 71,     TK_BREAK = 72,      TK_CONTINUE = 73,   TK_LOCAL = 74,      TK_ARROW = 75;
const TK_TRUE = 76,       TK_FALSE = 77,      TK_NUMBER = 78,     TK_DOUBLE = 79,     TK_STRING = 80;
const TK_REGEXP = 81,     TK_NULL = 82,       TK_THIS = 83,       TK_DELETE = 84,     TK_CONST = 85;
const TK_QLBRACK = 86,    TK_QLPAREN = 87,    TK_QDOT = 88,       TK_ASEXP = 89,      TK_ASAND = 90;
const TK_ASOR = 91,       TK_ASNULLISH = 92,  TK_NULLISH = 93,    TK_PLACEH = 94,     TK_TEMPLATE = 95;
const TK_IMPORT = 96,     TK_EXPORT = 97,     TK_EOF = 98,        TK_COMMENT = 99,    TK_ERROR = 100;


const documents = {};

function clockms() {
	const tv = clock(true);

	return tv[0] * 1000 + tv[1] / 1000000;
}

function compare_positions(pos1, pos2) {
	if (pos1.line != pos2.line)
		return pos1.line - pos2.line;

	return pos1.character - pos2.character;
}

function find_token_id_at_position(tokens, search_position, flags) {
	const use_next = (flags & FIND_PREFER_NEXT);
	let left = 0, right = length(tokens) - 1;
	let last_before = -1, first_after = -1;

	while (left <= right) {
		let mid = (left + right) / 2;
		let start_comparison = compare_positions(tokens[mid].start, search_position);
		let end_comparison = compare_positions(tokens[mid].end, search_position);

		if (start_comparison == 0 && !use_next && mid > 0 &&
		    compare_positions(tokens[mid - 1].end, search_position) == 0)
			return mid - 1;

		if (end_comparison == 0 && use_next && mid + 1 < length(tokens) &&
		    compare_positions(tokens[mid + 1].start, search_position) == 0)
			return mid + 1;

		if (start_comparison <= 0 && end_comparison >= 0)
			return mid;

		if (end_comparison < 0) {
			left = mid + 1;
			last_before = mid;
		}
		else {
			right = mid - 1;
			first_after = mid;
		}
	}

	if (flags & FIND_SKIP_SPACE) {
		if (use_next)
			return (first_after > -1) ? first_after : last_before;
		else
			return (last_before > -1) ? last_before : first_after;
	}

	return -1;
}

function find_token_at_position(tokens, search_position, flags) {
	const id = find_token_id_at_position(tokens, search_position, flags);
	return (id > -1) ? tokens[id] : null;
}

function find_scopes_at_position(scopes, search_position) {
	let matching_scopechain = [];

	for (let scope in scopes) {
		if (compare_positions(search_position, scope.start) >= 0 &&
		    compare_positions(search_position, scope.end) <= 0) {

			unshift(matching_scopechain, scope);
		}

		if (length(matching_scopechain) &&
		    compare_positions(scope.start, matching_scopechain[0].end) >= 0)
			break;
	}

	return matching_scopechain;
}

function find_variable_at_position(document, search_position) {
	let token = find_token_at_position(document.tokens, search_position);

	warn(`VAR-TOKEN: ${search_position} => ${token}\n`);

	if (token?.type == TK_LABEL) {
		let scopes = find_scopes_at_position(document.scopes, search_position);
		let name = token.value;

		for (let scope in scopes)
			for (let variable in scope.variables)
				if (variable.name == name) {
					warn(`VAR-CANDIDATE: ${variable}\n`);
					for (let ref in variable.references) {
						warn(`REF-CANDIDATE: ${ref.token} (${ref.token === token})\n`);
						if (ref.token == token)
							return variable;
					}
				}
	}

	return null;
}

function find_call_at_position(document, search_position) {
	let scopes = find_scopes_at_position(document.scopes, search_position);
	let call;

	for (let scope in scopes) {
		for (let variable in scope.variables) {
			if (index(variable.name, '.return.') == 0) {
				const s1 = variable.range.start;
				const e1 = variable.range.end;
				const len1 = e1.offset - s1.offset;

				if (compare_positions(search_position, s1) >= 0 &&
				    compare_positions(search_position, e1) < 0) {

					const s2 = call?.range?.start;
					const e2 = call?.range?.end;
					const len2 = e2?.offset - s2?.offset;

					if (!call || len1 < len2)
						call = variable;
				}
			}
		}
	}

	return call;
}

function format_type(typeSpec)
{
	for (let t in [ 'function', 'object', 'array', 'module' ])
		if (t in typeSpec)
			return t;

	for (let t in [ 'boolean', 'string', 'number', 'integer', 'double', 'null' ]) {
		if (typeSpec.type === t) {
			if (typeSpec.value !== null)
				return sprintf('(%s) %J', t, typeSpec.value);
			else
				return t;
		}
	}

	return '(unknown type)';
}

function format_typename(typespec) {
	switch (typespec?.type ?? 'unspec') {
	case 'unspec':   return '?';
	case 'any':      return '*';
	case 'typename': return typespec.typename;
	case 'union':    return join('|', map(typespec.union, format_typename));
	default:         return typespec.type;
	}
}

function format_detail(prefixText, labelText, typeSpec)
{
	let res = (typeSpec.constant ? 'const ' : '');

	res += prefixText + labelText;

	if ('function' in typeSpec) {
		res += '(';

		res += join(', ', map(typeSpec.function.arguments,
			(arg, i) => (arg.name ? `${arg.name}:` : '') + format_typename(arg.type)));

		res += ')';

		if (typeSpec.function.return)
			res += ' → ' + format_typename(typeSpec.function.return?.type);
	}
	else {
		res += ' : ' + format_type(typeSpec);
	}

	return res;
}

function handleInitialize(params) {
	return {
		capabilities: {
			textDocumentSync: 1,
			definitionProvider: true,
			referencesProvider: true,
			completionProvider: {
				resolveProvider: false,
				triggerCharacters: ['.', '['],
				completionItem: {
					labelDetailsSupport: true
				}
			},
			semanticTokensProvider: {
				//documentSelector: [
				//	{ language: 'ucode', scheme: 'file' }
				//],
				full: true,
				legend: {
					tokenTypes: TOKEN_TYPES,
					tokenModifiers: TOKEN_MODIFIERS
				}
			},
			signatureHelpProvider: {
				triggerCharacters: ['('],
				retriggerCharacters: [',']
			},
			renameProvider: {
				prepareProvider: true
			}
		}
	};
}

function quotePropertyName(propname, force) {
	if (!force && match(propname, /^[A-Za-z_][A-Za-z0-9_]*$/))
		return propname;

	if (index(propname, "'") != -1)
		return `"${replace(propname, /["\\]/g, (m) => `\\${m}`)}"`;

	return `'${replace(propname, /['\\]/g, (m) => `\\${m}`)}'`;
}

function format_label_detail(typespec) {
	if (typespec?.function) {
		let res = '(';

		for (let i, argspec in typespec.function.arguments ?? []) {
			if (i > 0)
				res += ', ';

			if (argspec.restarg)
				res += '...';

			res += argspec.name ?? format_typename(argspec.type);
		}

		res += ')';

		if (typespec.function.return) {
			res += ' → ';
			res += replace(
				format_typename(typespec.function.return?.type),
				/^.+\./, ''
			);
		}

		return res;
	}

	let res = ` : ${format_typename(typespec)}`;

	if (typespec.value != null)
		res += ` = ${typespec.value}`;

	return res;
}

function isTemplateSyntax(uri, text) {
	return (match(uri, /\.ut$/) || match(text, /^#!.*(\<utpl\>|[[:space:]]-[[:alnum:]]*T[[:alnum:]]*\>)/));
}

function logStructure(doc) {
	warn('-- DOCUMENT STRUCTURE --\n');

	for (let scope in doc.scopes) {
		warn(`Scope ${scope.start.line}:${scope.start.character}..${scope.end.line}:${scope.end.character}\n`);

		for (let var in scope.variables) {
			warn(`+ ${var.property ? 'Prop' : 'Var'} '${var.name}' ${var.range.start.line}:${var.range.start.character}..${var.range.end.line}:${var.range.end.character}\n`);

			for (let ref in var.references) {
				warn(`  + Ref ${ref.access} ${ref.location.line}:${ref.location.character}\n`);
			}
		}
	}

	warn('-- END STRUCTURE --\n');
}

function parseDocument(uri) {
	const document = documents[uri];
	const now = clockms();

	//warn(`Query <${uri}>: dirty=${doc.dirty} delta=${now - doc.changed}ms length=${length(doc.text)}\n`);

	if (document.tokens == null || (document.dirty /*&& now - doc.changed > 250*/)) {
		warn(`Reparsing ${uri} after ${now - document.changed}ms...\n`);

		const res = analyze(document.text, { raw_mode: !isTemplateSyntax(uri, document.text) });

		if (res) {
			for (let k, v in res)
				document[k] = v;

			document.dirty = false;
		}

		//logStructure(doc);

		return true;
	}

	return false;
}

function handlePropertyCompletion(document, position, propertyToken, closingToken, varspec, prefixText) {
	const start = propertyToken?.start;
	const end = closingToken?.end ?? position;
	const optional = (propertyToken.type == TK_QLBRACK || propertyToken.type == TK_QDOT);
	const bracketed = (propertyToken.type == TK_LBRACK || propertyToken.type == TK_QLBRACK);

	const completions = [];

	let jsType = varspec.jsdoc?.type;

	while (jsType?.type == 'typename' && document.typedefs[jsType.typename])
		jsType = document.typedefs[jsType.typename].type;

	const isArray = (jsType?.type == 'array');
	const proplist = isArray ? jsType?.array?.elements : jsType?.object?.properties;

	warn(`PROPLIST: ${isArray}:${proplist}\n`);

	for (let propidx, propspec in proplist) {
		let propname = isArray ? `${propidx}` : propidx;

		if (index(propname, prefixText) != 0)
			continue;

		const op = optional ? '?.' : '.';
		const op2 = optional ? '?.[' : '[';
		const propNameQuoted = quotePropertyName(propname, bracketed);

		let newText, labelText, filterText, sortText;

		if (isArray) {
			labelText = bracketed ? `[${propname}]` : propname;
			sortText = sprintf('%03d', propidx);
			newText = filterText = `${op2}${propidx}]`;
		}
		else {
			const st = optional ? (bracketed ? '?.[' : '?.') : (bracketed ? '[' : '.');
			const et = (bracketed ? ']' : '');

			labelText = propNameQuoted;
			filterText = `${st}${propNameQuoted}${et}`;
			sortText = propname;
			newText = (bracketed || propNameQuoted != propname)
				? `${op2}${propNameQuoted}]` : `${op}${propname}`;
		}

		const fnspec = propspec.type?.function;

		if (fnspec) {
			newText += length(fnspec.arguments)
				? `(\${1:${join(', ', map(fnspec.arguments, (arg, i) => arg.name ?? `arg${i}`))}})`
				: '(\${1})';
		}

		warn(`COMPLETION <<${start.line}:${start.character}..${end.line}:${end.character}|${substr(document.text, start.offset, end.character - start.character)}>> <<${filterText}>>\n`);

		push(completions, {
			label: labelText,
			labelDetails: {
				detail: format_label_detail(propspec.type),
				description: propspec.description ?? ''
			},
			filterText,
			textEdit: {
				newText,
				range: { start, end }
			},
			kind: (propspec.type?.type == 'function') ? KIND_METHOD : KIND_PROPERTY,
			detail: format_detail(propname, '', propspec.type),
			documentation: propspec.description ?? '',
			sortText,
			insertTextFormat: INSERT_FORMAT_SNIPPET
		});
	}

	return completions;
}

function handleVariableCompletion(document, position, variableToken) {
	const scopes = find_scopes_at_position(document.scopes, position);
	const start = variableToken?.start ?? position;
	const end = variableToken?.end ?? position;
	const varnameSeen = {};
	const completions = [];

	warn(`VAR-TOKEN: ${variableToken}\n`);

	for (let depth, scope in scopes) {
		for (let varspec in scope.variables) {
			if (varspec.property || ord(varspec.name) == 46)
				continue;

			if (variableToken && index(varspec.name, variableToken.value) !== 0)
				continue;

			if (compare_positions(start, varspec.range.start) <= 0)
				continue;

			if (compare_positions(start, varspec.range.end) > 0)
				continue;

			if (varnameSeen[varspec.name]++)
				continue;

			const fnspec = varspec.jsdoc?.type?.function;
			let newText = varspec.name;

			if (fnspec) {
				newText += length(fnspec.arguments)
					? `(\${1:${join(', ', map(fnspec.arguments, (arg, i) => arg.name ?? `arg${i}`))}})`
					: '(\${1})';
			}

			push(completions, {
				label: varspec.name,
				labelDetails: {
					detail: format_label_detail(varspec.jsdoc?.type),
					description: varspec.jsdoc?.subject ?? ''
				},
				filterText: variableToken?.value ?? '',
				textEdit: {
					newText,
					range: { start, end }
				},
				kind: fnspec ? KIND_FUNCTION : (varspec.jsdoc?.constant ? KIND_CONSTANT : KIND_VARIABLE),
				detail: format_detail(varspec.name, '', varspec.jsdoc?.type),
				documentation: varspec.jsdoc?.description ?? '',
				sortText: sprintf('%03d', depth),
				insertTextFormat: INSERT_FORMAT_SNIPPET
			});
		}
	}

	return completions;
}

function determineCompletionContext(document, position)
{
	let token_id = find_token_id_at_position(document.tokens, position);

	/* this should not happen */
	if (token_id == -1)
		return { type: 'variable' };

	/* if the determined token token is an EOF one, step back until we find the
	 * last non-eof, non-comment token */
    while (token_id > 0 && document.tokens[token_id].type in [ TK_EOF, TK_COMMENT ])
		token_id--;

	const tok = document.tokens[token_id];
	const isDot = tok.type in [ TK_DOT, TK_QDOT ];
	const isSub = tok.type in [ TK_LBRACK, TK_QLBRACK ];

	/* if the last token is a label, determine whether we're at a partially
	   typed property access or a variable read expression */
	if (tok.type == TK_LABEL) {
		for (let scope in find_scopes_at_position(document.scopes, position)) {
			// scan variables backwards as it is likely that the user types near
			// the end of the document
			for (let i = length(scope.variables); i > 0; i--) {
				const var = scope.variables[i - 1];

				if (var.property != true || length(var.references) != 1)
					continue;

				const ref = var.references[0];

				if (ref.access != 'declaration' || ref.token !== tok)
					continue;

				return {
					type: 'property',
					propertyToken: find_token_at_position(document.tokens, var.range.start),
					lhsVariable: var.base,
					rhsLabel: tok.value
				};
			}
		}

		// no matching property found, assume variable access
		return {
			type: 'variable',
			variableToken: tok
		};
	}

	/* otherwise, if it is a dot or left square bracket, find a property
	   reference whose range start matches the token */
	else if (isDot || isSub) {
		let etok;

		for (let i = 1; isSub && !etok && i <= 2; i++)
			if (document.tokens[token_id + i].type == TK_RBRACK)
				etok = document.tokens[token_id + i];

		for (let scope in find_scopes_at_position(document.scopes, position)) {
			// scan variables backwards as it is likely that the user types near
			// the end of the document
			for (let i = length(scope.variables); i > 0; i--) {
				const var = scope.variables[i - 1];

				if (var.property != true)
					continue;

				if (var.range.start.offset != tok.start.offset)
					continue;

				warn(`VAR: ${var}\n`);

				return {
					type: 'property',
					propertyToken: tok,
					closingToken: etok,
					lhsVariable: var.base,
					rhsLabel: ''
				};
			}
		}
	}

	/* in all other cases assume new variable completion */
	else {
		return { type: 'variable' };
	}
}

function handleCompletion(params) {
	const uri = params.textDocument.uri;
	const position = params.position;
	const document = documents[uri];

	parseDocument(uri);

	let ctx = determineCompletionContext(document, position);

	warn(`completionContext() = ${ctx}\n`);

	if (ctx?.type == 'property')
		return handlePropertyCompletion(document, position,
			ctx.propertyToken, ctx.closingToken, ctx.lhsVariable, ctx.rhsLabel);

	return handleVariableCompletion(document, position, ctx.variableToken);
}

function handleDefinition(params) {
	const uri = params.textDocument.uri;
	const position = params.position;
	const document = documents[uri];

	const varspec = find_variable_at_position(document, position);

	if (varspec) {
		const ref = varspec.references[0];

		if (ref != null && ref.access in [ 'declaration', 'write', 'update' ]) {
			return [
				{
					uri,
					range: {
						start: ref.token.start,
						end: ref.token.end
					}
				}
			];
		}
	}

	return [];
}

function handleReferences(params) {
	const uri = params.textDocument.uri;
	const document = documents[uri];
	const position = params.position;
	const varspec = find_variable_at_position(document, position);

	return map(varspec?.references ?? [], ref => ({
		uri,
		range: {
			start: ref.token.start,
			end: ref.token.end
		}
	}));
}

function handleSignatureHelp(params) {
	const uri = params.textDocument.uri;
	const document = documents[uri];
	const position = params.position;

	parseDocument(uri);

	const varspec = find_call_at_position(document, position);

	if (!varspec || !varspec.base || !varspec.base.jsdoc)
		return null;

	warn(`SIGNATURE: ${varspec}\n`);

	let jsType = varspec.base.jsdoc.type;

	while (jsType?.type == 'typename' && document.typedefs[jsType.typename])
		jsType = document.typedefs[jsType.typename].type;

	if (jsType?.type != 'function')
		return null;

	let label = varspec.base.name ?? varspec.name ?? 'function';
	let offsets = [];

	label += '(';

	for (let i, arg in jsType.function.arguments) {
		if (i > 0) label += ', ';

		push(offsets, length(label), length(label) + length(arg.name));

		label += arg.name;
	}

	label += ')';

	let activeParameter = 0;

	let start_token_id = find_token_id_at_position(document.tokens, varspec.range.start, FIND_PREFER_NEXT);
	let end_token_id = find_token_id_at_position(document.tokens, position, FIND_SKIP_SPACE);

	warn(`START-TOKEN@${varspec.range.start}: ${document.tokens[start_token_id]}\n`);
	warn(`TOKEN-RANGE: ${start_token_id + 1}..${end_token_id}\n`);

	for (let i = start_token_id + 1, stack = []; i < end_token_id; i++) {
		let tt = document.tokens[i].type;

		warn(`TOK: ${tt}\n`);

		if (tt == TK_LPAREN || tt == TK_QLPAREN)
			push(stack, TK_RPAREN);
		else if (tt == TK_LBRACK || tt == TK_QLBRACK)
			push(stack, TK_RBRACK);
		else if (tt == TK_LBRACE)
			push(stack, TK_RBRACE);
		else if (length(stack) > 0 && tt == stack[-1])
			pop(stack);
		else if (length(stack) == 0 && tt == TK_COMMA)
			activeParameter++;
		else if (length(stack) == 0 && tt == TK_RPAREN)
			break;
	}

	warn(`ACTIVE-PARAM: ${activeParameter}\n`);

	return {
		signatures: [
			{
				label,
				documentation: varspec.base.jsdoc.description ?? '',
				parameters: map(jsType.function?.arguments, arg => ({
					label: [
						offsets[activeParameter * 2 + 0],
						offsets[activeParameter * 2 + 1]
					],
					documentation: arg.description ?? ''
				}))
			}
		],
		activeSignature: 0,
		activeParameter
	};
}

function handleSemanticTokens(params) {
	const uri = params.textDocument.uri;
	const document = documents[uri];

	let tokens = [];
	let prevLine = 0;
	let prevColumn = 0;

	for (let token in document.tokens) {
		let tokenLine = token.start.line;
		let tokenStart = token.start.character;

		if (token.start.line < token.end.line) {
			let s = substr(document.text, token.start.offset, token.end.offset - token.start.offset);
			//warn(`ML-TOKEN[${s}]\n`);
			for (let i, ln in split(s, '\n')) {
				let deltaStart = (i > 0 || tokenLine > prevLine) ? tokenStart : tokenStart - prevColumn;
				let deltaLine = (i > 0) ? 1 : tokenLine - prevLine;

				push(tokens,
					deltaLine,
					deltaStart,
					length(ln),
					token.semanticType,
					token.semanticModifiers
				);

				tokenStart = 0;
			}
		}
		else {
			let deltaStart = (tokenLine > prevLine) ? tokenStart : tokenStart - prevColumn;
			let deltaLine = tokenLine - prevLine;

			push(tokens,
				deltaLine,
				deltaStart,
				token.end.offset - token.start.offset,
				token.semanticType,
				token.semanticModifiers
			);
		}

		prevLine = token.end.line;
		prevColumn = tokenStart;
	}

	warn(`Sending ${length(tokens)}/${length(document.tokens)}/${length(document.text)} tokens...\n`);

	return { data: tokens };
}

function updateDocument(uri, text) {
	const now = clockms();
	const doc = documents[uri] ??= { uri, changed: 0 };

	const delta = now - doc.changed;

	const old = doc.text ?? '';
	const new = text;

	if (false && doc.text != null) {
		writefile('/tmp/ucode-server-old.txt', doc.text);
		writefile('/tmp/ucode-server-new.txt', text);

		const diff = popen('diff -pab -u /tmp/ucode-server-old.txt /tmp/ucode-server-new.txt', 'r');
		warn(`-- DOCUMENT UPDATE (${length(text)} bytes) --\n`);
		warn(diff.read('all'));
		warn('-- END UPDATE --\n');
		diff.close();
	}

	doc.changed = now;
	doc.dirty = true;
	doc.text = text;

	return delta;
}

function sendDiagnostics(doc) {
	let diagnostics = [];

	for (let error in doc.errors ?? []) {
		push(diagnostics, {
			range: {
				start: error.start,
				end: error.end
			},
			severity: SEVERITY_ERROR,
			message: error.message,
			source: 'ucode-ast'
		});
	}

	return {
		jsonrpc: '2.0',
		method: 'textDocument/publishDiagnostics',
		params: { uri: doc.uri, diagnostics }
	};
}

function handleTextDocumentDidOpen(params) {
	let uri = params.textDocument.uri;
	let text = params.textDocument.text;

	updateDocument(uri, text);
	parseDocument(uri);

	return sendDiagnostics(documents[uri]);
}

function handleTextDocumentDidChange(params) {
	let uri = params.textDocument.uri;

	for (let change in params.contentChanges)
		if ('text' in change)
			updateDocument(uri, change.text);
}

function handleTextDocumentDidClose(params) {
	let uri = params.textDocument.uri;

	delete documents[uri];
}

function handlePrepareRename(params) {
	const uri = params.textDocument.uri;
	const document = documents[uri];
	const position = params.position;

	parseDocument(uri);

	warn(`FIND TOKEN...\n`);

	const token = find_token_at_position(document.tokens, position);

	warn(`TOKEN: ${token}\n`);

	if (!token || token.type != TK_LABEL)
		return null;

	for (let scope in find_scopes_at_position(document.scopes, token.start)) {
		warn(`SCOPE...\n`);
		for (let varspec in scope.variables) {
			if (type(varspec.name) != 'string' || ord(varspec.name) == 46)
				continue;

			for (let ref in varspec.references) {
				if (ref.token === token) {
					warn(`RET???\n`);
					return {
						range: {
							start: ref.token.start,
							end: ref.token.end
						},
						placeholder: ref.token.value
					};
				}
			}
		}
	}
}

function handleRename(params) {
	const uri = params.textDocument.uri;
	const document = documents[uri];
	const position = params.position;

	parseDocument(uri);

	const token = find_token_at_position(document.tokens, position);

	if (!token || token.type != TK_LABEL)
		return null;

	for (let scope in find_scopes_at_position(document.scopes, token.start)) {
		for (let varspec in scope.variables) {
			if (type(varspec.name) != 'string' || ord(varspec.name) == 46)
				continue;

			for (let ref in varspec.references) {
				if (ref.token === token) {
					return {
						changes: {
							[uri]: map(varspec.references, r => ({
								range: {
									start: r.token.start,
									end: r.token.end
								},
								newText: params.newName
							}))
						}
					};
				}
			}
		}
	}
}

return {
	handle: function(rpc) {
		if (rpc.method == "initialize")
			return handleInitialize(rpc.params);
		else if (rpc.method == "textDocument/completion")
			return handleCompletion(rpc.params);
		else if (rpc.method == 'textDocument/definition')
			return handleDefinition(rpc.params);
		else if (rpc.method == 'textDocument/references')
			return handleReferences(rpc.params);
		else if (rpc.method == 'textDocument/signatureHelp')
			return handleSignatureHelp(rpc.params);
		else if (rpc.method == 'textDocument/semanticTokens/full')
			return handleSemanticTokens(rpc.params);
		else if (rpc.method == "textDocument/didOpen")
			return handleTextDocumentDidOpen(rpc.params);
		else if (rpc.method == "textDocument/didChange")
			return handleTextDocumentDidChange(rpc.params);
		else if (rpc.method == 'textDocument/didClose')
			return handleTextDocumentDidClose(rpc.params);
		else if (rpc.method == 'textDocument/prepareRename')
			return handlePrepareRename(rpc.params);
		else if (rpc.method == 'textDocument/rename')
			return handleRename(rpc.params);
	},

	idle: function() {
		const now = clockms();
		const replies = [];

		for (let uri, doc in documents) {
			if (parseDocument(uri))
				push(replies, sendDiagnostics(doc));
		}

		return replies;
	}
};

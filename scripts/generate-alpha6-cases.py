"""Invented syntax controls and same-position credential attacks; no session data."""
import json
from pathlib import Path

cases = []
secret = "M8zR4vK7nP2qW6xAq9"


def keep(family, text):
    cases.append(dict(family=family, input=text, expected=text))


def hide(family, text, value=secret):
    cases.append(dict(family=family, input=text, secret=value))


forms = {
    "regex": "/widget[a-z]+/g",
    "call": "readWidget(input)",
    "member": "widget.credentials",
    "operator": "widget.primary + widget.secondary",
    "logical": "widget.primary && widget.secondary",
    "conditional": "widget.ready ? widget.primary : widget.secondary",
    "object": "{widget: 1}",
    "nested_object": "{widget: {count: 1}}",
    "array": "[widget.primary, widget.secondary]",
    "template": "${widget.credentials}",
    "identifier": "widgetPassword",
    "uppercase": "WIDGET_CREDENTIAL",
}
for family, expression in forms.items():
    for key in ["password", "token", "session_id", "PASSWORD"]:
        for prefix in ["", "const "]:
            text = f"{prefix}{key} = {expression};"
            keep(family, text)
            for quote in ['"', "'", "`"]:
                # Backtick templates already have a reviewed exemption.
                if family == "template" and quote == "`":
                    continue
                hide(family + "_quoted_literal", f"{prefix}{key} = {quote}{secret}{quote};")
            hide(family + "_literal_sibling", f"{prefix}{key} = {secret};")
            for tail in [f" {secret}", f"#{secret}", f" //{secret}", f" + \"{secret}\""]:
                hide(family + "_tail", f"{prefix}{key} = {expression}{tail};")
            for sep in ["%3D", r"\u003d", r"\x3d", "%253d"]:
                hide(family + "_encoded_tail", f"{prefix}{key} {sep} {expression} {secret};")
            hide(family + "_embedded", f'{prefix}{key} = readWidget("{secret}");')
            for literal in ["plain-secret", "123456"]:
                for tail in [f" {literal}", f" #{literal}", f" //{literal}", f' + "{literal}"']:
                    hide(family + "_short_tail", f"{prefix}{key} = {expression}{tail};", literal)
            for quote in ['"', "'"]:
                hide(family + "_quoted_syntax", f"{prefix}{key} = {quote}{expression}{quote};", expression)
    for literal in ["123456", "-246810", "12.375"]:
        hide(family + "_numeric", f"const token = {literal};", literal)

for expression in ["String", "Option<String>", "Vec<Widget>", "WidgetCredentials"]:
    for key in ["password", "token", "PASSWORD"]:
        for wrapper in ["{}", "struct Widget {{ {} }}", "interface Widget {{ {} }}"]:
            keep("type", wrapper.format(f"{key}: {expression},"))
            hide("type_tail", wrapper.format(f"{key}: {expression} {secret},"))
            hide("type_quote", wrapper.format(f'{key}: "{secret}",'))
            hide("type_embedded", wrapper.format(f'{key}: Option<"{secret}">,'))

for text in ["secret = {", "const token = {", "const {token: widgetToken} = widget;", "let [token, password] = widget;"]:
    keep("syntax_or_bind", text)
for expression in [f'{{widget: "{secret}"}}', f'[{secret}]', f'{{password: 123456}}', f'{{widget: {{token: "{secret}"}}}}']:
    value = "123456" if "123456" in expression else secret
    hide("structure_literal", f"const token = {expression};", value)
for text in [f"secret = {{ {secret}", f"secret = {{\npassword = {secret}"]:
    hide("fragment_tail", text)

for prefix in ["relay_ag_", "relay_pa_", "relay_ws_", "relay_id_"]:
    symbol = prefix + "widget_transport_adapter"
    keep("provider_symbol", f"use {symbol};")
    for text in [f'const token = "{symbol}";', f"token={symbol}", f"https://{symbol}.example.invalid/path", f"use {symbol}{secret};", f"use {symbol} {secret};"]:
        hide("provider_symbol_attack", text, secret if secret in text else symbol)
    for literal in ["plain-secret", "123456"]:
        hide("provider_symbol_short_tail", f"use {symbol} {literal};", literal)
    for text in [f'use "{symbol}";', f"use %22{symbol}%22;", f"use {prefix}widget_TRANSPORT_adapter;"]:
        hide("provider_symbol_quote_encoding_case", text, symbol if symbol in text else prefix + "widget_TRANSPORT_adapter")

for text in ['case "token": return parseToken(input);', "case 'password': return widget.credentials;", 'grep -rn "access token": src/ | head', "rg 'access token': src/ | head", '{"Key": "raw/v1/widget.jsonl.zst"}', "mysql --password -h db", "mysql --password --host db"]:
    keep("upstream_pr11", text)
for text in [f'case "token": return "{secret}";', f'case "token": return parseToken("{secret}");', f'grep -rn "access token": {secret}', f'grep -rn "access token": src/{secret} | head', f'{{"credentials":{{"Key":"{secret}"}}}}', f'mysql --password={secret} -h db', f'mysql --password "-{secret}" -h db', f'mysql --password -{secret} -h db']:
    hide("upstream_pr11_literal", text)

path = Path(__file__).resolve().parents[1] / "eval/alpha6_syntax_cases.json"
path.write_text(json.dumps(cases, indent=2) + "\n")
print(f"{len(cases)} invented cases")

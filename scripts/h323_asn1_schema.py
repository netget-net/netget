#!/usr/bin/env python3
"""Generate src/server/h323/schema.rs — the PER schema tables NetGet's H.323 codec walks — from
the ITU ASN.1 modules H323-MESSAGES (H.225.0 12/2009), H235-SECURITY-MESSAGES (H.235.0 09/2005)
and MULTIMEDIA-SYSTEM-CONTROL (H.245 v15).

The modules are the ITU's own, as Wireshark redistributes them; fetch them at a pinned commit:

    base=https://raw.githubusercontent.com/wireshark/wireshark/<commit>/epan/dissectors/asn1
    curl -sSLO $base/h225/H323-MESSAGES.asn
    curl -sSLO $base/h235/H235-SECURITY-MESSAGES.asn
    curl -sSL -o MULTIMEDIA-SYSTEM-CONTROL.asn $base/h245/MULTIMEDIA-SYSTEM-CONTROL.asn
    python3 scripts/h323_asn1_schema.py <dir with the three files> > src/server/h323/schema.rs

This is a parser for the subset of X.680 those three modules use, not for ASN.1 at large. It
keeps only what changes an ALIGNED PER encoding: SEQUENCE/CHOICE components with OPTIONAL and
the extension marker, SEQUENCE/SET OF with SIZE, INTEGER value ranges, ENUMERATED, OCTET and BIT
STRING sizes, known-multiplier character strings with SIZE and FROM, OBJECT IDENTIFIER, BOOLEAN
and NULL. WITH COMPONENTS constraints are not PER-visible and are dropped. Parameterized types
(SIGNED{}, ENCRYPTED{}, HASHED{}) and information-object types become Opaque: the codec refuses
them in a root position and steps over them by length where they are an extension addition.

Only the types reachable from the roots below are emitted.
"""
import re
import sys
import pathlib

MODULE_FILES = {
    "H225": "H323-MESSAGES.asn",
    "H235": "H235-SECURITY-MESSAGES.asn",
    "H245": "MULTIMEDIA-SYSTEM-CONTROL.asn",
}
MODULE_NAMES = {
    "H323-MESSAGES": "H225",
    "H235-SECURITY-MESSAGES": "H235",
    "MULTIMEDIA-SYSTEM-CONTROL": "H245",
}
ROOTS = [
    ("H225", "RasMessage"),
    ("H225", "H323-UserInformation"),
    ("H245", "MultimediaSystemControlMessage"),
    ("H245", "OpenLogicalChannel"),
]

TOKEN = re.compile(
    r"""\s*(?:
      (?P<str>"[^"]*")
    | (?P<num>-?\d+)
    | (?P<sym>::=|\.\.\.|\.\.|\[\[|\]\]|[{}()\[\],|.&<>@!^;:])
    | (?P<id>[A-Za-z][A-Za-z0-9-]*)
    )""",
    re.X,
)


def strip_comments(text):
    out = []
    for line in text.split("\n"):
        res = []
        i = 0
        in_comment = False
        in_str = False
        while i < len(line):
            if not in_comment and line[i] == '"':
                in_str = not in_str
                res.append(line[i])
                i += 1
                continue
            if not in_str and line.startswith("--", i):
                in_comment = not in_comment
                i += 2
                continue
            if not in_comment:
                res.append(line[i])
            i += 1
        out.append("".join(res))
    return "\n".join(out)


def tokenize(text):
    text = strip_comments(text)
    pos = 0
    toks = []
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = TOKEN.match(text, pos)
        if not m:
            raise SystemExit(f"cannot tokenize at {text[pos:pos+40]!r}")
        pos = m.end()
        toks.append(m.group(m.lastgroup))
    return toks


class Parser:
    def __init__(self, toks):
        self.t = toks
        self.i = 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expect(self, tok):
        got = self.next()
        if got != tok:
            raise SystemExit(f"expected {tok!r}, got {got!r} near {self.t[self.i-5:self.i+5]}")

    def skip_balanced(self, open_, close):
        depth = 0
        while True:
            tok = self.next()
            if tok == open_:
                depth += 1
            elif tok == close:
                depth -= 1
                if depth == 0:
                    return

    # ---- module ----------------------------------------------------------------------------
    def module(self):
        name = self.next()
        while self.next() != "BEGIN":
            pass
        imports = {}
        types = {}
        if self.peek() == "IMPORTS":
            self.next()
            names = []
            while True:
                tok = self.next()
                if tok == ";":
                    break
                if tok == "FROM":
                    mod = self.next()
                    for n in names:
                        imports[n] = MODULE_NAMES.get(mod, mod)
                    names = []
                    if self.peek() == "{":
                        self.skip_balanced("{", "}")
                    continue
                if tok in (",", "{", "}"):
                    continue
                names.append(tok)
        if self.peek() == "EXPORTS":
            while self.next() != ";":
                pass
        while self.peek() not in (None, "END"):
            ident = self.next()
            if self.peek() == "{":
                # Parameterized assignment: NAME {Param} ::= Type.
                self.skip_balanced("{", "}")
                self.expect("::=")
                self.type_()
                types[ident] = {"kind": "opaque", "why": f"parameterized type {ident}{{}}"}
                continue
            if ident[0].islower():
                # Value assignment: name Type ::= value.
                self.type_()
                self.expect("::=")
                if self.peek() == "{":
                    self.skip_balanced("{", "}")
                else:
                    self.next()
                continue
            self.expect("::=")
            types[ident] = self.type_()
        return name, imports, types

    # ---- types -----------------------------------------------------------------------------
    def type_(self):
        tok = self.next()
        if tok in ("SEQUENCE", "SET"):
            if self.peek() == "{":
                t = self.components(tok)
            else:
                size = None
                if self.peek() == "(":
                    size = self.constraint().get("size")
                elif self.peek() == "SIZE":
                    self.next()
                    size = self.constraint().get("value")
                self.expect("OF")
                if self.peek(1) and self.peek()[0].islower() and self.peek(1)[0].isupper() and self.peek(1) not in ("OF",):
                    # SEQUENCE OF name Type (named element)
                    if self.peek() not in ("SEQUENCE", "SET", "CHOICE"):
                        self.next()
                item = self.type_()
                t = {"kind": "seqof", "size": size or (0, None, False), "item": item}
        elif tok == "CHOICE":
            t = self.components("CHOICE")
        elif tok == "ENUMERATED":
            self.expect("{")
            root, ext, in_ext = [], [], False
            while True:
                tok = self.next()
                if tok == "}":
                    break
                if tok == ",":
                    continue
                if tok == "...":
                    in_ext = True
                    continue
                if self.peek() == "(":
                    self.skip_balanced("(", ")")
                (ext if in_ext else root).append(tok)
            t = {"kind": "enum", "root": root, "ext": ext if in_ext else None}
        elif tok == "INTEGER":
            if self.peek() == "{":
                self.skip_balanced("{", "}")
            t = {"kind": "int", "range": None}
        elif tok == "BOOLEAN":
            t = {"kind": "bool"}
        elif tok == "NULL":
            t = {"kind": "null"}
        elif tok == "OBJECT":
            self.expect("IDENTIFIER")
            t = {"kind": "oid"}
        elif tok == "OCTET":
            self.expect("STRING")
            t = {"kind": "octets", "size": None}
        elif tok == "BIT":
            self.expect("STRING")
            if self.peek() == "{":
                self.skip_balanced("{", "}")
            t = {"kind": "bits", "size": None}
        elif tok in ("IA5String", "BMPString", "NumericString", "PrintableString"):
            t = {"kind": "chars", "chars": tok, "size": None, "alphabet": None}
        elif tok == "GeneralString":
            # Not a known-multiplier string: PER writes a length in octets and the octets.
            t = {"kind": "chars", "chars": tok, "size": None, "alphabet": None}
        elif tok == "TYPE-IDENTIFIER":
            self.expect(".")
            self.expect("&")
            self.next()
            t = {"kind": "opaque", "why": "TYPE-IDENTIFIER.&Type"}
        else:
            if self.peek() == "{":
                self.skip_balanced("{", "}")
                t = {"kind": "opaque", "why": f"parameterized type {tok}{{}}"}
            else:
                t = {"kind": "ref", "name": tok}
        while self.peek() == "(":
            c = self.constraint()
            t = apply_constraint(t, c)
        return t

    def components(self, kind):
        self.expect("{")
        root, ext, in_ext = [], [], False
        while True:
            tok = self.peek()
            if tok == "}":
                self.next()
                break
            if tok == ",":
                self.next()
                continue
            if tok == "...":
                self.next()
                if in_ext:
                    # Second ellipsis: the extension addition list ends; anything after it is
                    # root again. None of these modules use that form.
                    raise SystemExit("extension insertion point pairs are not supported")
                in_ext = True
                continue
            if tok == "[[":
                raise SystemExit("version brackets are not supported")
            name = self.next()
            ty = self.type_()
            optional = False
            if self.peek() == "OPTIONAL":
                self.next()
                optional = True
            elif self.peek() == "DEFAULT":
                raise SystemExit("DEFAULT is not supported")
            (ext if in_ext else root).append({"name": name, "type": ty, "optional": optional})
        if kind == "CHOICE":
            return {"kind": "choice", "root": root, "ext": ext if in_ext else None}
        return {"kind": "seq", "root": root, "ext": ext if in_ext else None}

    def constraint(self):
        """Parse one parenthesised constraint; returns {'value': (lb, ub, ext)} or
        {'size': (...)} or {'from': str} or {} for a non-PER-visible constraint."""
        self.expect("(")
        result = {}
        while True:
            result.update(self.constraint_element())
            if self.peek() == "^":
                # An intersection, as in SIZE (1) ^ FROM ("0123456789#*ABCD!"): both apply.
                self.next()
                continue
            break
        if self.peek() == ",":
            # An extensible constraint: (lb..ub, ...) or (SIZE (lb..ub), ...).
            self.next()
            self.expect("...")
            for key in ("value", "size"):
                if result.get(key):
                    lb, ub, _ = result[key]
                    result[key] = (lb, ub, True)
        if self.peek() == "|":
            raise SystemExit("union constraints are not supported")
        self.expect(")")
        return result

    def constraint_element(self):
        tok = self.peek()
        if tok == "SIZE":
            self.next()
            return {"size": self.constraint().get("value")}
        if tok == "FROM":
            self.next()
            self.expect("(")
            s = self.next()
            self.expect(")")
            return {"from": s.strip('"')}
        if tok == "(":
            return self.constraint()
        if tok == "WITH" or (tok[0].isalpha() and tok[0].isupper() and tok not in ("MIN", "MAX")):
            # WITH COMPONENTS, or a table/type constraint: neither is PER-visible.
            self.skip_to_close()
            return {}
        lb = self.value()
        ub = lb
        if self.peek() == "..":
            self.next()
            ub = self.value()
        return {"value": (lb, ub, False)}

    def skip_to_close(self):
        """Consume tokens up to (not including) the ')' closing the current constraint."""
        depth = 0
        while True:
            tok = self.peek()
            if tok in ("(", "{"):
                depth += 1
            elif tok in (")", "}"):
                if depth == 0:
                    return
                depth -= 1
            self.next()

    def value(self):
        tok = self.next()
        if tok == "MIN":
            return None
        if tok == "MAX":
            return None
        return int(tok)


def apply_constraint(t, c):
    t = dict(t)
    if not c:
        return t
    if t["kind"] == "ref":
        t.setdefault("constraints", []).append(c)
        return t
    if t["kind"] == "int" and "value" in c:
        t["range"] = c["value"]
    elif t["kind"] in ("octets", "bits") and "size" in c:
        t["size"] = c["size"]
    elif t["kind"] == "chars":
        if "size" in c:
            t["size"] = c["size"]
        if "from" in c:
            t["alphabet"] = c["from"]
    elif t["kind"] == "seqof" and "size" in c:
        t["size"] = c["size"]
    elif t["kind"] in ("opaque",):
        pass
    else:
        raise SystemExit(f"constraint {c} on {t['kind']}")
    return t


# ---- emission ------------------------------------------------------------------------------

class Emitter:
    def __init__(self, modules):
        self.modules = modules  # mod -> (imports, types)
        self.entries = []  # (name, rust expr) filled in order
        self.index = {}  # key -> index
        self.anon_index = {}

    def resolve(self, mod, name):
        imports, types = self.modules[mod]
        if name in types:
            return mod, name
        if name in imports:
            return self.resolve(imports[name], name)
        raise SystemExit(f"{mod}: unknown type {name}")

    def named(self, mod, name):
        mod, name = self.resolve(mod, name)
        key = (mod, name)
        if key not in self.index:
            idx = len(self.entries)
            self.index[key] = idx
            self.entries.append(None)
            t = self.modules[mod][1][name]
            self.entries[idx] = (f"{mod}.{name}", self.render(mod, f"{name}", t))
        return self.index[key]

    def anon(self, mod, path, t):
        # Anonymous types are shared by shape: every INTEGER(0..255) in the modules is one entry.
        expr = self.render(mod, path, t)
        if expr not in self.anon_index:
            self.anon_index[expr] = len(self.entries)
            self.entries.append((f"{mod}.{path}", expr))
        return self.anon_index[expr]

    def type_index(self, mod, path, t):
        if t["kind"] == "ref" and not t.get("constraints"):
            return self.named(mod, t["name"])
        if t["kind"] == "ref":
            # A constrained reference: the referenced type with these constraints applied.
            rmod, rname = self.resolve(mod, t["name"])
            base = dict(self.modules[rmod][1][rname])
            while base["kind"] == "ref":
                cons = base.get("constraints", [])
                rmod, rname = self.resolve(rmod, base["name"])
                nb = dict(self.modules[rmod][1][rname])
                for c in cons:
                    nb = apply_constraint(nb, c)
                base = nb
            for c in t["constraints"]:
                base = apply_constraint(base, c)
            return self.anon(rmod, path, base)
        return self.anon(mod, path, t)

    def render(self, mod, path, t):
        k = t["kind"]
        if k == "ref":
            target = self.type_index(mod, path, t)
            return f"Ty::Alias({target})"
        if k == "null":
            return "Ty::Null"
        if k == "bool":
            return "Ty::Boolean"
        if k == "oid":
            return "Ty::Oid"
        if k == "opaque":
            return f"Ty::Opaque({rust_str(t['why'])})"
        if k == "int":
            r = t["range"]
            if r is None:
                return "Ty::Int(Range { lb: None, ub: None, ext: false })"
            lb, ub, ext = r
            return f"Ty::Int(Range {{ lb: {opt(lb)}, ub: {opt(ub)}, ext: {str(ext).lower()} }})"
        if k == "enum":
            root = ", ".join(rust_str(n) for n in t["root"])
            ext = "None" if t["ext"] is None else "Some(&[" + ", ".join(rust_str(n) for n in t["ext"]) + "])"
            return f"Ty::Enum {{ root: &[{root}], ext: {ext} }}"
        if k in ("octets", "bits"):
            name = "Octets" if k == "octets" else "Bits"
            return f"Ty::{name}({size(t['size'])})"
        if k == "chars":
            kind = {"IA5String": "Ia5", "BMPString": "Bmp", "NumericString": "Numeric",
                    "PrintableString": "Printable", "GeneralString": "General"}[t["chars"]]
            alpha = "None" if t["alphabet"] is None else f"Some({rust_str(t['alphabet'])})"
            return f"Ty::Chars {{ kind: CharKind::{kind}, size: {size(t['size'])}, alphabet: {alpha} }}"
        if k == "seqof":
            item = self.type_index(mod, path + ".item", t["item"])
            return f"Ty::SeqOf {{ size: {size(t['size'])}, item: {item} }}"
        if k in ("seq", "choice"):
            def fields(lst):
                out = []
                for f in lst:
                    idx = self.type_index(mod, path + "." + f["name"], f["type"])
                    out.append(f"Field {{ name: {rust_str(f['name'])}, ty: {idx}, optional: {str(f['optional']).lower()} }}")
                return "&[" + ", ".join(out) + "]"
            root = fields(t["root"])
            ext = "None" if t["ext"] is None else f"Some({fields(t['ext'])})"
            name = "Seq" if k == "seq" else "Choice"
            return f"Ty::{name} {{ root: {root}, ext: {ext} }}"
        raise SystemExit(f"cannot render {k}")


def opt(v):
    return "None" if v is None else f"Some({v})"


def size(s):
    if s is None:
        return "Size { lb: 0, ub: None, ext: false }"
    lb, ub, ext = s
    return f"Size {{ lb: {lb if lb is not None else 0}, ub: {opt(ub)}, ext: {str(ext).lower()} }}"


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def const_name(mod, name):
    return f"{mod}_{name}".upper().replace("-", "_")


def main():
    d = pathlib.Path(sys.argv[1])
    modules = {}
    for key, fname in MODULE_FILES.items():
        toks = tokenize((d / fname).read_text(encoding="utf-8", errors="replace"))
        _, imports, types = Parser(toks).module()
        modules[key] = (imports, types)
    em = Emitter(modules)
    roots = [(m, n, em.named(m, n)) for m, n in ROOTS]
    print("// @generated")
    print("//! ALIGNED PER schema tables for H.225.0 (12/2009), H.235.0 (09/2005) and H.245 v15.")
    print("//!")
    print("//! GENERATED by `scripts/h323_asn1_schema.py` from the ITU ASN.1 modules — do not edit by")
    print("//! hand; regenerate (the script's header says how). Only types reachable from the roots")
    print("//! named below are present. Index `n` in [`TYPES`] is named by `NAMES[n]`.")
    print("#![allow(clippy::all)]")
    print("use super::per::{CharKind, Field, Range, Size, Ty};")
    print()
    for m, n, idx in roots:
        print(f"pub const {const_name(m, n)}: u16 = {idx};")
    print()
    print("#[rustfmt::skip]")
    print(f"pub static NAMES: [&str; {len(em.entries)}] = [")
    for name, _ in em.entries:
        print(f"    {rust_str(name)},")
    print("];")
    print()
    print("#[rustfmt::skip]")
    print(f"pub static TYPES: [Ty; {len(em.entries)}] = [")
    for i, (name, expr) in enumerate(em.entries):
        print(f"    /* {i} {name} */ {expr},")
    print("];")


if __name__ == "__main__":
    main()

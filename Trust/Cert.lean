import Lean
import Trust.Marks
import Trust.Hash

/-!
# Trust certificates

One person's assertion about one declaration, keyed by its semantic hash rather
than its name.  `Trust.Hash` explains why that key: the hash is computed over
the definitional closure, so it covers the whole subtree beneath a declaration
and stops meaning anything the moment any of it changes.

Signing happens here, on the machine that holds the key, by handing the bytes
to `gpg`.  A private key is never read by this program and never leaves the
machine — the server takes public keys only, and a design where it could take
more would be a worse design however carefully it behaved.
-/

namespace Trust

open Lean

/-- The part of a certificate that gets signed. -/
structure Claim where
  decl : String
  hash : String
  hasher : String
  repo : String
  commit : String
  toolchain : String
  /-- RFC 3339, UTC. -/
  asserted : String
  note : String := ""
  deriving Inhabited, Repr

/--
Escape a string the way `JSON.stringify` does.

Written out rather than delegated to `Lean.Json`, because these bytes are what
a signature is made over and the server recomputes them in JavaScript: the two
have to agree exactly, down to which characters are escaped.  `JSON.stringify`
escapes the quote, the backslash and the C0 controls, and leaves everything
else — including all non-ASCII — alone.
-/
def escapeJsonString (s : String) : String :=
  s.foldl (init := "") fun out c =>
    match c with
    | '"' => out ++ "\\\""
    | '\\' => out ++ "\\\\"
    | '\n' => out ++ "\\n"
    | '\r' => out ++ "\\r"
    | '\t' => out ++ "\\t"
    | c =>
      if c.val < 0x20 then
        -- \b and \f are the only other short forms JSON.stringify uses.
        if c.val == 0x08 then out ++ "\\b"
        else if c.val == 0x0c then out ++ "\\f"
        else
          let hex := String.ofList (Nat.toDigits 16 c.val.toNat)
          out ++ "\\u" ++ "".pushn '0' (4 - hex.length) ++ hex
      else
        out.push c

/--
The exact bytes a signature covers.

Fields in a fixed (alphabetical) order with no incidental whitespace, matching
`server/src/certificate.ts`.  Anything looser and a signature would verify on
the machine that made it and nowhere else.
-/
def Claim.canonical (c : Claim) : String :=
  let field (k v : String) : String := "\"" ++ k ++ "\":\"" ++ escapeJsonString v ++ "\""
  "{" ++ String.intercalate "," [
    field "asserted" c.asserted,
    field "commit" c.commit,
    field "decl" c.decl,
    field "hash" c.hash,
    field "hasher" c.hasher,
    field "note" c.note,
    field "repo" c.repo,
    field "toolchain" c.toolchain] ++ "}"

instance : ToJson Claim where
  toJson c := Json.mkObj [
    ("decl", c.decl), ("hash", c.hash), ("hasher", c.hasher), ("repo", c.repo),
    ("commit", c.commit), ("toolchain", c.toolchain), ("asserted", c.asserted),
    ("note", c.note)]

instance : FromJson Claim where
  fromJson? j := do
    let get (k : String) : Except String String :=
      match j.getObjValAs? String k with
      | .ok v => .ok v
      | .error _ => if k == "note" then .ok "" else .error s!"claim.{k} is required"
    return {
      decl := ← get "decl", hash := ← get "hash", hasher := ← get "hasher",
      repo := ← get "repo", commit := ← get "commit", toolchain := ← get "toolchain",
      asserted := ← get "asserted", note := ← get "note" }

/--
A signed withdrawal.

Hiding a row in one database is not a withdrawal once certificates travel: the
copies that already left are not that database's to take back.  So a revocation
is signed by the same key that made the assertion, and carries the same weight
wherever it arrives.

A revocation suppresses the certificates with the same fingerprint, hash and
hasher whose `asserted` is not later than `revoked` — so re-issuing afterwards
reinstates, and needs no second message.  See §6 of `FEDERATION.md`.
-/
structure Revocation where
  /-- The key whose assertion is being withdrawn. -/
  fingerprint : String
  hash : String
  hasher : String
  /-- Why, in the signer's own words.  May be empty, never absent. -/
  reason : String := ""
  /-- RFC 3339, UTC. -/
  revoked : String
  deriving Inhabited, Repr

/-- The bytes a revocation's signature covers.  Same rules as `Claim.canonical`. -/
def Revocation.canonical (r : Revocation) : String :=
  let field (k v : String) : String := "\"" ++ k ++ "\":\"" ++ escapeJsonString v ++ "\""
  "{" ++ String.intercalate "," [
    field "fingerprint" r.fingerprint,
    field "hash" r.hash,
    field "hasher" r.hasher,
    field "reason" r.reason,
    field "revoked" r.revoked] ++ "}"

instance : ToJson Revocation where
  toJson r := Json.mkObj [
    ("fingerprint", r.fingerprint), ("hash", r.hash), ("hasher", r.hasher),
    ("reason", r.reason), ("revoked", r.revoked)]

instance : FromJson Revocation where
  fromJson? j := do
    let get (k : String) : Except String String :=
      match j.getObjValAs? String k with
      | .ok v => .ok v
      | .error _ => if k == "reason" then .ok "" else .error s!"revocation.{k} is required"
    return {
      fingerprint := ← get "fingerprint", hash := ← get "hash", hasher := ← get "hasher",
      reason := ← get "reason", revoked := ← get "revoked" }

/-- A claim, plus the signature over its canonical bytes when it has one. -/
structure Certificate where
  claim : Claim
  signature : Option String := none
  deriving Inhabited

instance : ToJson Certificate where
  toJson c :=
    let base := [("claim", toJson c.claim), ("canonical", Json.str c.claim.canonical)]
    Json.mkObj (base ++ (match c.signature with
      | some s => [("signature", Json.str s)]
      | none => []))

instance : FromJson Certificate where
  fromJson? j := do
    let claim ← fromJson? (← j.getObjVal? "claim")
    return { claim, signature := (j.getObjValAs? String "signature").toOption }

/--
An entry as it travels between nodes.

The public key goes with it.  That costs a couple of kilobytes and makes the
entry self-contained: whoever receives it can finish the check without a second
round trip to a key server they would then have to trust.
-/
structure Entry where
  claim : Claim
  signature : String
  /-- Armored public key, whose fingerprint must be the one below. -/
  key : String
  fingerprint : String
  deriving Inhabited

instance : ToJson Entry where
  toJson e := Json.mkObj [
    ("claim", toJson e.claim), ("signature", e.signature),
    ("key", e.key), ("fingerprint", e.fingerprint)]

instance : FromJson Entry where
  fromJson? j := do
    return {
      claim := ← fromJson? (← j.getObjVal? "claim")
      signature := ← j.getObjValAs? String "signature"
      key := ← j.getObjValAs? String "key"
      fingerprint := ← j.getObjValAs? String "fingerprint" }

/-- A revocation as it travels: signed, and carrying the key that signed it. -/
structure SignedRevocation where
  revocation : Revocation
  signature : String
  key : String
  fingerprint : String
  deriving Inhabited

instance : ToJson SignedRevocation where
  toJson r := Json.mkObj [
    ("revocation", toJson r.revocation), ("signature", r.signature),
    ("key", r.key), ("fingerprint", r.fingerprint)]

instance : FromJson SignedRevocation where
  fromJson? j := do
    return {
      revocation := ← fromJson? (← j.getObjVal? "revocation")
      signature := ← j.getObjValAs? String "signature"
      key := ← j.getObjValAs? String "key"
      fingerprint := ← j.getObjValAs? String "fingerprint" }

/-- What a node hands over: entries, withdrawals, and where to resume. -/
structure Bundle where
  protocol : String := "trust/1"
  origin : String := ""
  entries : Array Entry := #[]
  revocations : Array SignedRevocation := #[]
  cursor : String := ""
  /-- False when the sender truncated; a receiver resumes from `cursor`. -/
  complete : Bool := true
  deriving Inhabited

instance : ToJson Bundle where
  toJson b := Json.mkObj [
    ("protocol", b.protocol), ("origin", b.origin),
    ("entries", toJson b.entries), ("revocations", toJson b.revocations),
    ("cursor", b.cursor), ("complete", toJson b.complete)]

instance : FromJson Bundle where
  fromJson? j := do
    let arr (k : String) : Except String Json :=
      match j.getObjVal? k with
      | .ok v => .ok v
      | .error _ => .ok (Json.arr #[])
    return {
      protocol := (j.getObjValAs? String "protocol").toOption.getD ""
      origin := (j.getObjValAs? String "origin").toOption.getD ""
      entries := ← fromJson? (← arr "entries")
      revocations := ← fromJson? (← arr "revocations")
      cursor := (j.getObjValAs? String "cursor").toOption.getD ""
      -- Absent means complete: a sender that truncates has to say so.
      complete := (j.getObjValAs? Bool "complete").toOption.getD true }

/-- The current time as RFC 3339 in UTC, which is how a claim dates itself. -/
def nowRFC3339 : IO String := do
  let out ← IO.Process.output { cmd := "date", args := #["-u", "+%Y-%m-%dT%H:%M:%SZ"] }
  if out.exitCode == 0 then return out.stdout.trimAscii.toString
  return "1970-01-01T00:00:00Z"

/-- Build a claim for `declName`, hashing it with the semantic hasher. -/
def issueClaim (env : Environment) (declName : Name) (repo commit note : String) :
    IO (Except String Claim) := do
  match ← semanticHasher.hash env declName with
  | none => return .error s!"`{declName}` is not in this environment"
  | some hash =>
    let commit ← if commit.isEmpty then currentCommit else pure commit
    return .ok {
      decl := s!"{privateToUserName declName}"
      hash
      hasher := semanticHasher.name
      repo
      commit
      toolchain := Lean.versionString
      asserted := ← nowRFC3339
      note }

/--
Sign some bytes by handing them to `gpg`.

The bytes go in on stdin and the armoured signature comes back on stdout, so
nothing touching the key is written to disk here and no key material passes
through this process at all.  `--local-user` picks the key when there is more
than one.
-/
def signBytes (text : String) (keyId : String) : IO (Except String String) := do
  let args := #["--armor", "--detach-sign", "--output", "-"]
    ++ (if keyId.isEmpty then #[] else #["--local-user", keyId])
  let child ← IO.Process.spawn {
    cmd := "gpg", args, stdin := .piped, stdout := .piped, stderr := .piped }
  let (stdin, child) ← child.takeStdin
  stdin.putStr text
  stdin.flush
  -- Closing stdin is what tells gpg the message is complete.
  let stdout ← IO.asTask child.stdout.readToEnd .dedicated
  let stderr ← child.stderr.readToEnd
  let code ← child.wait
  let signature ← IO.ofExcept stdout.get
  if code != 0 then
    return .error s!"gpg failed ({code}): {stderr.trimAscii}"
  return .ok signature

/-- Sign a claim: the canonical bytes, and nothing else. -/
def signClaim (claim : Claim) (keyId : String) : IO (Except String String) :=
  signBytes claim.canonical keyId

/-- Sign a withdrawal.  Only the key that asserted something may withdraw it. -/
def signRevocation (revocation : Revocation) (keyId : String) : IO (Except String String) :=
  signBytes revocation.canonical keyId

/--
Check a signature against the local keyring, without asking any server.

`extraArgs` is how the bundle checker points gpg at a keyring of its own
instead; empty here, so this uses the keys you already have.
-/
def verifyBytes (text signature : String) (extraArgs : Array String := #[]) :
    IO (Except String Unit) := do
  IO.FS.withTempFile fun sigHandle sigPath => do
    sigHandle.putStr signature
    sigHandle.flush
    let child ← IO.Process.spawn {
      cmd := "gpg", args := extraArgs ++ #["--verify", sigPath.toString, "-"],
      stdin := .piped, stdout := .piped, stderr := .piped }
    let (stdin, child) ← child.takeStdin
    stdin.putStr text
    stdin.flush
    let _ ← child.stdout.readToEnd
    let stderr ← child.stderr.readToEnd
    let code ← child.wait
    if code == 0 then return .ok () else return .error stderr.trimAscii.toString

/-- Check a claim's signature locally. -/
def verifyClaim (claim : Claim) (signature : String) : IO (Except String Unit) :=
  verifyBytes claim.canonical signature

/--
Send a certificate to a server.

Through `curl` because Lean has no HTTP client, and with a bearer token because
the browser's cookie session is not something a command line can hold.  The
token authenticates *who is publishing*; it is not what makes the certificate
trustworthy — the signature is, and the server cannot forge that.
-/
def postJson (url token body : String) : IO (Except String String) := do
  let auth := if token.isEmpty then #[] else #["-H", s!"Authorization: Bearer {token}"]
  -- `--data-binary @-` reads the body from stdin, so a note containing a quote
  -- or a newline can never be parsed as another argument.
  let child ← IO.Process.spawn {
    cmd := "curl"
    args := #["-sS", "-X", "POST", url, "-H", "Content-Type: application/json"]
      ++ auth ++ #["--data-binary", "@-"]
    stdin := .piped, stdout := .piped, stderr := .piped }
  let (stdin, child) ← child.takeStdin
  stdin.putStr body
  stdin.flush
  let stdout ← IO.asTask child.stdout.readToEnd .dedicated
  let stderr ← child.stderr.readToEnd
  let code ← child.wait
  let response ← IO.ofExcept stdout.get
  if code != 0 then return .error s!"curl failed ({code}): {stderr.trimAscii}"
  return .ok response.trimAscii.toString

def publishCertificate (cert : Certificate) (server token : String) :
    IO (Except String String) := do
  let body := Json.compress (Json.mkObj (
    [("claim", toJson cert.claim)] ++ (match cert.signature with
      | some s => [("signature", Json.str s)]
      | none => [])))
  postJson s!"{server}/api/certificates" token body

/--
Publish a withdrawal.

No token: the signature is the authorisation.  Only the key that made an
assertion can withdraw it, and demanding an account as well would mean somebody
who has lost access to theirs can never take a certificate back.
-/
def publishRevocation (revocation : Revocation) (signature key server : String) :
    IO (Except String String) := do
  let body := Json.compress (Json.mkObj [
    ("revocation", toJson revocation), ("signature", Json.str signature),
    ("key", Json.str key)])
  postJson s!"{server}/api/revocations" "" body

/-- Fetch a URL, through `curl` because Lean has no HTTP client. -/
def httpGet (url : String) : IO (Except String String) := do
  let out ← IO.Process.output {
    cmd := "curl", args := #["-sS", "--fail-with-body", "-H", "Accept: application/json", url] }
  if out.exitCode != 0 then
    return .error s!"curl failed ({out.exitCode}): {out.stderr.trimAscii}{out.stdout.trimAscii}"
  return .ok out.stdout

/-- Fetch a bundle from a node's public export. -/
def fetchBundle (server : String) (since : String) : IO (Except String Bundle) := do
  let query := if since.isEmpty then "" else s!"?since={since}"
  match ← httpGet s!"{server}/api/certificates/export{query}" with
  | .error msg => return .error msg
  | .ok text =>
    match Json.parse text >>= fromJson? with
    | .ok bundle => return .ok bundle
    | .error msg => return .error s!"unreadable bundle: {msg}"

/-- Ask a node who vouches for a hash, as a bundle. -/
def fetchCertificates (server hash hasher : String) : IO (Except String Bundle) := do
  let hasherQuery := if hasher.isEmpty then "" else s!"&hasher={hasher}"
  match ← httpGet s!"{server}/api/certificates?hash={hash}{hasherQuery}&format=bundle" with
  | .error msg => return .error msg
  | .ok text =>
    match Json.parse text >>= fromJson? with
    | .ok bundle => return .ok bundle
    | .error msg => return .error s!"unreadable bundle: {msg}"

/--
A gpg home directory of its own, thrown away afterwards.

Checking a bundle means checking signatures against keys that arrived *with*
it, and importing strangers' keys into someone's real keyring to do that would
be a rude and lasting side effect of a read-only command.  Everything happens
in a directory that exists for the length of one check.
-/
private def withEphemeralGpgHome (act : String → IO α) : IO α := do
  let out ← IO.Process.output { cmd := "mktemp", args := #["-d"] }
  if out.exitCode != 0 then throw <| IO.userError "could not create a temporary directory"
  let home := out.stdout.trimAscii.toString
  try
    act home
  finally
    -- Best effort: a leftover temporary directory is untidy, not dangerous.
    let _ ← IO.Process.output { cmd := "rm", args := #["-rf", home] }

/-- Whether `needle` occurs in `haystack`. -/
private def containsSubstring (haystack needle : String) : Bool :=
  (haystack.splitOn needle).length > 1

/--
The fingerprint of the secret key that will do the signing.

A revocation names the key it withdraws *inside the bytes that get signed*, so
this has to be the key gpg will actually use — guessing wrong produces a
perfectly valid signature over a claim about somebody else's key, which every
node then rejects for a reason that sounds like a bug.

With several secret keys and no `--key`, this refuses rather than picking one:
gpg's own default depends on `gpg.conf`, and reproducing that guess here is how
the two quietly disagree.
-/
def secretFingerprint (keyId : String) : IO (Except String String) := do
  let selector := if keyId.isEmpty then #[] else #[keyId]
  let out ← IO.Process.output {
    cmd := "gpg", args := #["--list-secret-keys", "--with-colons"] ++ selector }
  if out.exitCode != 0 then
    return .error s!"gpg could not list your secret keys: {out.stderr.trimAscii}"
  -- In `--with-colons` output a primary key is a `sec:` record, and the `fpr:`
  -- record that follows it carries the fingerprint in field ten.
  let mut fingerprints : Array String := #[]
  let mut afterSec := false
  for line in out.stdout.splitOn "\n" do
    if line.startsWith "sec:" then
      afterSec := true
    else if line.startsWith "fpr:" && afterSec then
      afterSec := false
      let fields := line.splitOn ":"
      if h : 9 < fields.length then
        fingerprints := fingerprints.push (fields[9].toLower)
  match fingerprints.toList with
  | [] => return .error "no secret key found; gpg has nothing to sign with"
  | [only] => return .ok only
  | _ =>
    if keyId.isEmpty then
      return .error "you have several secret keys; say which with --key"
    else
      return .ok fingerprints[0]!

/-- The armoured public half of a key, to travel with what it signed. -/
def exportPublicKey (keyId : String) : IO (Except String String) := do
  let out ← IO.Process.output { cmd := "gpg", args := #["--armor", "--export", keyId] }
  if out.exitCode != 0 || out.stdout.trimAscii.isEmpty then
    return .error s!"gpg could not export the public key for `{keyId}`"
  return .ok out.stdout

/-- What a bundle check found, per entry. -/
inductive EntryVerdict where
  /-- The signature checks out against the key the entry carries. -/
  | ok (decl hash fingerprint : String)
  /-- It does not, and the entry is worth nothing. -/
  | bad (decl hash reason : String)
  deriving Inhabited

def EntryVerdict.isBad : EntryVerdict → Bool
  | .bad .. => true
  | .ok .. => false

def EntryVerdict.describe : EntryVerdict → String
  | .ok decl hash fingerprint => s!"ok       {decl} {hash} signed by {fingerprint}"
  | .bad decl hash reason => s!"BAD      {decl} {hash}: {reason}"

/--
Check every entry in a bundle, here, against the keys it carries.

This is the command that makes a server unnecessary rather than trusted: it
repeats, locally, precisely the check the server claims to have done.  The rules
are §3.4 of `FEDERATION.md` — the key must be a public key, its fingerprint must
be the one the entry claims, and the signature must verify over the canonical
bytes.
-/
def verifyBundle (bundle : Bundle) : IO (Array EntryVerdict) := do
  -- Checked once, up front.  Without it, a missing gpg reports every entry as
  -- unreadable, which reads as "these certificates are bad" — the most
  -- misleading answer this command could give, and about the most alarming.
  let available ← try
      let out ← IO.Process.output { cmd := "gpg", args := #["--version"] }
      pure (out.exitCode == 0)
    catch _ => pure false
  if !available then
    throw <| IO.userError "gpg is not available, and checking signatures needs it"
  withEphemeralGpgHome fun home => do
    let mut verdicts := #[]
    for entry in bundle.entries do
      verdicts := verdicts.push (← verifyEntry home entry)
    return verdicts
where
  /-- Import the entry's key into the throwaway home, then check against it. -/
  verifyEntry (home : String) (entry : Entry) : IO EntryVerdict := do
    let decl := entry.claim.decl
    let hash := entry.claim.hash
    if containsSubstring entry.key "PRIVATE KEY BLOCK" then
      return .bad decl hash "the entry carries a private key"
    if !containsSubstring entry.key "BEGIN PGP PUBLIC KEY BLOCK" then
      return .bad decl hash "the entry carries no public key"
    let gpgHome := #["--homedir", home, "--batch", "--quiet"]
    IO.FS.withTempFile fun keyHandle keyPath => do
      keyHandle.putStr entry.key
      keyHandle.flush
      let imported ← IO.Process.output {
        cmd := "gpg", args := gpgHome ++ #["--import", keyPath.toString] }
      if imported.exitCode != 0 then
        return .bad decl hash s!"the key could not be read: {imported.stderr.trimAscii}"
      -- The fingerprint has to match what the entry claims, or a valid
      -- signature would be attributed to whoever the entry named.
      let listed ← IO.Process.output {
        cmd := "gpg", args := gpgHome ++ #["--with-colons", "--fingerprint"] }
      let claimed := entry.fingerprint.toLower
      if !containsSubstring listed.stdout.toLower claimed then
        return .bad decl hash "the fingerprint does not match the key it travels with"
      match ← verifyBytes entry.claim.canonical entry.signature gpgHome with
      | .error reason => return .bad decl hash (reason.replace "\n" "; ")
      | .ok _ => return .ok decl hash claimed

end Trust

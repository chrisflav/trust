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
          let hex := (Nat.toDigits 16 c.val.toNat).asString
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
Sign a claim by handing its canonical bytes to `gpg`.

The bytes go in on stdin and the armoured signature comes back on stdout, so
nothing touching the key is written to disk here and no key material passes
through this process at all.  `--local-user` picks the key when there is more
than one.
-/
def signClaim (claim : Claim) (keyId : String) : IO (Except String String) := do
  let args := #["--armor", "--detach-sign", "--output", "-"]
    ++ (if keyId.isEmpty then #[] else #["--local-user", keyId])
  let child ← IO.Process.spawn {
    cmd := "gpg", args, stdin := .piped, stdout := .piped, stderr := .piped }
  let (stdin, child) ← child.takeStdin
  stdin.putStr claim.canonical
  stdin.flush
  -- Closing stdin is what tells gpg the message is complete.
  let stdout ← IO.asTask child.stdout.readToEnd .dedicated
  let stderr ← child.stderr.readToEnd
  let code ← child.wait
  let signature ← IO.ofExcept stdout.get
  if code != 0 then
    return .error s!"gpg failed ({code}): {stderr.trimAscii}"
  return .ok signature

/-- Check a signature locally, without asking any server whether it is good. -/
def verifyClaim (claim : Claim) (signature : String) : IO (Except String Unit) := do
  IO.FS.withTempFile fun sigHandle sigPath => do
    sigHandle.putStr signature
    sigHandle.flush
    let child ← IO.Process.spawn {
      cmd := "gpg", args := #["--verify", sigPath.toString, "-"],
      stdin := .piped, stdout := .piped, stderr := .piped }
    let (stdin, child) ← child.takeStdin
    stdin.putStr claim.canonical
    stdin.flush
    let _ ← child.stdout.readToEnd
    let stderr ← child.stderr.readToEnd
    let code ← child.wait
    if code == 0 then return .ok () else return .error stderr.trimAscii.toString

/--
Send a certificate to a server.

Through `curl` because Lean has no HTTP client, and with a bearer token because
the browser's cookie session is not something a command line can hold.  The
token authenticates *who is publishing*; it is not what makes the certificate
trustworthy — the signature is, and the server cannot forge that.
-/
def publishCertificate (cert : Certificate) (server token : String) :
    IO (Except String String) := do
  let body := Json.compress (Json.mkObj (
    [("claim", toJson cert.claim)] ++ (match cert.signature with
      | some s => [("signature", Json.str s)]
      | none => [])))
  -- `--data-binary @-` reads the body from stdin, so a note containing a quote
  -- or a newline can never be parsed as another argument.
  let child ← IO.Process.spawn {
    cmd := "curl"
    args := #["-sS", "-X", "POST", s!"{server}/api/certificates",
      "-H", "Content-Type: application/json",
      "-H", s!"Authorization: Bearer {token}",
      "--data-binary", "@-"]
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

end Trust

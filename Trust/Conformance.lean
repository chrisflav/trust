import Trust.Cert
import Trust.Federation
import Trust.Pgp
import Trust.Time

/-!
# Conformance vectors

`FEDERATION.md` is written as a protocol because the other end is not this code.
These are the bytes that sentence has to survive contact with: the canonical
form of a claim and of a revocation, entries that must be accepted, and one
entry for each way §3.4 says to refuse.

They matter more after the rewrite than before it.  There used to be three
implementations of the canonical bytes — Lean, the server, the browser — pinned
to each other by a golden vector copied between test files.  With the server and
the CLI in Lean there are two, and the second is the browser's, which is the one
that has to be independent: it is where a reader checks a signature they were
handed.  These files are the whole of the contract between them.

Generated rather than written by hand, because a vector that was typed is a
vector that says what someone thought the implementation did.
-/

namespace Trust

namespace Conformance

/-- A claim with every awkward character in it, because that is where implementations differ. -/
def awkwardClaim : Claim where
  decl := "Nat.gcd"
  hash := "629db3ae6e206484"
  hasher := "semantic-v1"
  repo := "trust"
  commit := "0a5a0e6"
  toolchain := "4.31.0"
  asserted := "2026-07-18T16:14:12Z"
  note := "reviewed by hand: \"quotes\", \\backslash, and ünïcodé"

/-- A note that tries to close the string and add a field of its own. -/
def hostileClaim : Claim :=
  { awkwardClaim with note := "\",\"hash\":\"0000000000000000" }

/-- Every C0 control JSON.stringify has a short form for, and one it does not. -/
def controlClaim : Claim :=
  { awkwardClaim with
    note := "tab:\tnewline:\nreturn:\rbackspace:formfeed:bell:" }

def emptyNoteClaim : Claim := { awkwardClaim with note := "" }

def sampleRevocation : Revocation where
  fingerprint := "3acde6becb49b9dd602fc41ed3b69ff50b2226c8"
  hash := "629db3ae6e206484"
  hasher := "semantic-v1"
  reason := "the proof was wrong"
  revoked := "2026-07-18T16:14:12Z"

def emptyReasonRevocation : Revocation := { sampleRevocation with reason := "" }

open Lean in
/-- A claim and the bytes a signature over it covers. -/
private def claimVector (name : String) (c : Claim) : Json :=
  Json.mkObj [("name", Json.str name), ("claim", toJson c), ("canonical", Json.str c.canonical)]

open Lean in
private def revocationVector (name : String) (r : Revocation) : Json :=
  Json.mkObj [("name", Json.str name), ("revocation", toJson r),
              ("canonical", Json.str r.canonical)]

open Lean in
/-- §3.2 and §6.1: the canonical bytes, for anything that has to reproduce them. -/
def claimVectors : Json :=
  Json.arr #[
    claimVector "awkward-characters" awkwardClaim,
    claimVector "note-forging-a-field" hostileClaim,
    claimVector "c0-controls" controlClaim,
    claimVector "empty-note" emptyNoteClaim]

open Lean in
def revocationVectors : Json :=
  Json.arr #[
    revocationVector "with-reason" sampleRevocation,
    revocationVector "empty-reason" emptyReasonRevocation]

open Lean in
/-- §2: a descriptor, complete, as a node publishes it. -/
def descriptorVector : Json :=
  toJson (α := Federation.Descriptor) {
    url := "https://trust.example.org", name := "example",
    software := "trust-server/0.2.0", certificates := 1200, peers := 3 }

/-- Why an entry vector is in the file: to be accepted, or to be refused for a named reason. -/
inductive Expectation where
  | accept
  | reject (rule : String)

def Expectation.toJson : Expectation → Lean.Json
  | .accept => Lean.Json.mkObj [("accept", Lean.Json.bool true)]
  | .reject rule => Lean.Json.mkObj [("accept", Lean.Json.bool false), ("rule", Lean.Json.str rule)]

/-! ## Entries

An entry vector needs a real signature, so these are generated against a key
made for the occasion.  Only the public half is written out; the private half
lives for the length of one command and is thrown away with its home directory.
A committed private key would be a worse way to do this and would look, to
anyone scanning the repository, exactly like an accident.
-/

private def gpgIn (home : System.FilePath) (args : Array String) (stdin : String := "") :
    IO (UInt32 × String) := do
  let child ← IO.Process.spawn {
    cmd := "gpg",
    args := #["--homedir", home.toString, "--batch", "--quiet", "--no-tty",
              "--passphrase", "", "--pinentry-mode", "loopback"] ++ args,
    stdin := .piped, stdout := .piped, stderr := .piped }
  let (h, child) ← child.takeStdin
  h.putStr stdin
  h.flush
  let out ← IO.asTask child.stdout.readToEnd .dedicated
  let _ ← child.stderr.readToEnd
  let code ← child.wait
  return (code, ← IO.ofExcept out.get)

/-- A key with a real signing subkey, which is the ordinary shape and the awkward one. -/
private def makeKey (home : System.FilePath) (uid : String) :
    IO (String × String × String) := do
  let _ ← gpgIn home #["--quick-gen-key", uid, "ed25519", "sign", "never"]
  let fingerprints := fun (listing : String) => Id.run do
    let mut primary := ""
    let mut sub := ""
    let mut afterPub := false
    let mut afterSub := false
    for line in listing.splitOn "\n" do
      if line.startsWith "pub:" then afterPub := true; afterSub := false
      else if line.startsWith "sub:" then afterSub := true; afterPub := false
      else if line.startsWith "fpr:" then
        let fields := line.splitOn ":"
        if h : 9 < fields.length then
          if afterPub then primary := fields[9].toLower; afterPub := false
          else if afterSub then sub := fields[9].toLower; afterSub := false
    return (primary, sub)
  let (_, listing0) ← gpgIn home #["--with-colons", "--list-keys", uid]
  let (primary0, _) := fingerprints listing0
  let _ ← gpgIn home #["--quick-add-key", primary0, "ed25519", "sign", "never"]
  let (_, listing) ← gpgIn home #["--with-colons", "--list-keys", uid]
  let (primary, sub) := fingerprints listing
  let (_, pub) ← gpgIn home #["--armor", "--export", uid]
  return (primary, sub, pub)

open Lean in
private def entryJson (name : String) (entry : Entry) (expectation : Expectation) : Json :=
  Json.mkObj [("name", Json.str name), ("entry", toJson entry),
              ("canonical", Json.str entry.claim.canonical),
              ("expect", expectation.toJson)]

/--
Every entry a receiver must accept, and one for each way §3.4 says to refuse.

Rule 5's case is the one worth having in a file other implementations read: gpg
signs with a subkey, so an entry that names the subkey's fingerprint has a
perfectly good signature and must still be refused, because §3.4 rule 3 asks for
the primary.  An implementation that reports the wrong one of those two passes
every other test in this file.
-/
def generateEntries : IO Lean.Json := do
  IO.FS.withTempDir fun home => do
    let (primary, subkey, publicKey) ← makeKey home "Conformance Key <conformance@example.org>"
    let claim := awkwardClaim
    let (_, signature) ← gpgIn home
      #["--armor", "--detach-sign", "--local-user", "conformance@example.org", "--output", "-"]
      claim.canonical
    let base : Entry := { claim, signature, key := publicKey, fingerprint := primary }
    return Lean.Json.arr #[
      entryJson "well-formed" base .accept,
      entryJson "fingerprint-is-the-subkey"
        { base with fingerprint := subkey } (.reject "3.4/3"),
      entryJson "fingerprint-is-a-stranger"
        { base with fingerprint := "0000000000000000000000000000000000000000" } (.reject "3.4/3"),
      entryJson "signature-over-other-bytes"
        { base with claim := { claim with note := "tampered" } } (.reject "3.4/4"),
      entryJson "carries-a-private-key"
        { base with key := "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----" }
        (.reject "3.4/2"),
      entryJson "no-key-at-all" { base with key := "not a key" } (.reject "3.4/2"),
      entryJson "hash-is-not-lower-case-hex"
        { base with claim := { claim with hash := "629DB3AE6E206484" } } (.reject "3.4/1"),
      entryJson "hash-is-too-short"
        { base with claim := { claim with hash := "629db3ae" } } (.reject "3.4/1"),
      entryJson "asserted-is-not-a-timestamp"
        { base with claim := { claim with asserted := "yesterday" } } (.reject "3.4/1")]

/-- Write the vectors.  `--out` is a directory; each file is one section of the protocol. -/
def write (dir : System.FilePath) : IO Unit := do
  IO.FS.createDirAll dir
  let file (name : String) (payload : Lean.Json) : IO Unit :=
    IO.FS.writeFile (dir / name) (payload.pretty ++ "\n")
  file "claims.json" claimVectors
  file "revocations.json" revocationVectors
  file "descriptor.json" descriptorVector
  file "entries.json" (← generateEntries)

/--
Check the committed vectors against this implementation.

Two questions, and they are different: do the canonical bytes still come out the
same, and does acceptance still decide what the file says it decides.  The first
is what a signature depends on; the second is what a node's answer depends on.
-/
def check (dir : System.FilePath) (verifier : Verifier := defaultVerifier) :
    IO (Array String) := do
  let mut problems := #[]
  let read (name : String) : IO (Option Lean.Json) := do
    if ← System.FilePath.pathExists (dir / name) then
      match Lean.Json.parse (← IO.FS.readFile (dir / name)) with
      | .ok j => return some j
      | .error _ => return none
    else return none
  match ← read "claims.json" with
  | none => problems := problems.push "claims.json is missing or unreadable"
  | some j =>
    for vector in (j.getArr?.toOption.getD #[]) do
      let name := (vector.getObjValAs? String "name").toOption.getD "?"
      match vector.getObjVal? "claim" >>= Lean.fromJson? (α := Claim),
            vector.getObjValAs? String "canonical" with
      | .ok claim, .ok expected =>
        if claim.canonical != expected then
          problems := problems.push s!"claims.json/{name}: canonical bytes differ"
      | _, _ => problems := problems.push s!"claims.json/{name}: unreadable"
  match ← read "revocations.json" with
  | none => problems := problems.push "revocations.json is missing or unreadable"
  | some j =>
    for vector in (j.getArr?.toOption.getD #[]) do
      let name := (vector.getObjValAs? String "name").toOption.getD "?"
      match vector.getObjVal? "revocation" >>= Lean.fromJson? (α := Revocation),
            vector.getObjValAs? String "canonical" with
      | .ok r, .ok expected =>
        if r.canonical != expected then
          problems := problems.push s!"revocations.json/{name}: canonical bytes differ"
      | _, _ => problems := problems.push s!"revocations.json/{name}: unreadable"
  match ← read "entries.json" with
  | none => problems := problems.push "entries.json is missing or unreadable"
  | some j =>
    if !(← verifier.available) then
      problems := problems.push s!"SKIPPED entries.json: {verifier.name} is not available"
    else
      for vector in (j.getArr?.toOption.getD #[]) do
        let name := (vector.getObjValAs? String "name").toOption.getD "?"
        match vector.getObjVal? "entry" >>= Lean.fromJson? (α := Entry) with
        | .error _ => problems := problems.push s!"entries.json/{name}: unreadable"
        | .ok entry =>
          let shouldAccept :=
            (vector.getObjVal? "expect" >>= (·.getObjValAs? Bool "accept")).toOption.getD false
          let accepted := (← Federation.acceptEntry entry verifier) matches .ok _
          if accepted != shouldAccept then
            problems := problems.push
              s!"entries.json/{name}: expected {if shouldAccept then "accept" else "reject"}, got {if accepted then "accept" else "reject"}"
  return problems

end Conformance

end Trust

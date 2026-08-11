/-!
# Signature verification

Everything a node believes about an entry it did not originate, it believes
because it checked a signature (`FEDERATION.md` §1).  This module is that check,
and nothing else in the project is allowed to be.

There is no OpenPGP implementation in Lean, so the check goes out to `gpg`.
That is a backend, not the design: the interface below is a record, in the same
way `Trust.Hash` makes the hasher a record, so a native implementation can
replace the subprocess without the server or the CLI noticing.  Every verdict
says which verifier produced it, for the same reason every hash records its
hasher.

The private key never enters this process.  Signing hands bytes to `gpg` on
stdin and takes an armoured signature back on stdout; a design where a key could
be read here would be a worse design however carefully it behaved.
-/

namespace Trust

/--
What a check found.

`signingKey` and `primaryKey` are the two fingerprints that matter and are
routinely confused.  A signature is made by a *subkey*; the entry names the
*primary*.  Reporting only one of them is how a valid signature gets attributed
to a key that did not make it, which is `FEDERATION.md` §3.4 rule 5 and the rule
it calls the one most easily got wrong.
-/
structure Verdict where
  /-- Whether the signature verified, by this verifier, over exactly these bytes. -/
  ok : Bool
  /-- Fingerprint of the (sub)key that actually made the signature, lower case. -/
  signingKey : String := ""
  /-- Fingerprint of the primary key that subkey belongs to, lower case. -/
  primaryKey : String := ""
  /-- Which verifier said so. -/
  verifier : String := ""
  /-- Why not, when `ok` is false. -/
  reason : String := ""
  deriving Inhabited, Repr

/-- A verdict that failed, with a reason. -/
def Verdict.bad (verifier reason : String) : Verdict :=
  { ok := false, verifier, reason }

/--
The signature check, as an interface.

`verify` is deliberately given the *armoured public key* rather than a keyring
handle: an entry travels with its key (§3.3), so a check needs no state, no key
server, and no prior arrangement with the sender.
-/
structure Verifier where
  /-- Which implementation this is; recorded in every verdict it produces. -/
  name : String
  /-- Check `signature` over exactly `bytes`, against `key`. -/
  verify : (bytes signature key : String) → IO Verdict
  /-- The primary fingerprint of an armoured public key, lower case hex. -/
  fingerprint : (key : String) → IO (Except String String)
  /-- Whether this verifier can run at all here. -/
  available : IO Bool

namespace Gpg

/-- Whether `needle` occurs in `haystack`. -/
private def contains (haystack needle : String) : Bool :=
  (haystack.splitOn needle).length > 1

/-- `gpg` arguments that keep it out of the user's real keyring and quiet. -/
private def isolated (home : System.FilePath) : Array String :=
  #["--homedir", home.toString, "--batch", "--quiet", "--no-tty",
    "--no-default-keyring", "--trust-model", "always"]

/--
The primary fingerprint of every key in a keyring, lower case.

`--with-colons` output lists a `pub:` record for each primary key and an `fpr:`
record after it holding the fingerprint in field ten; subkeys arrive as `sub:`
followed by their own `fpr:`.  Only the ones that follow a `pub:` are primaries,
and telling them apart is the whole point of reading this rather than grepping.
-/
private def primaryFingerprintsIn (listing : String) : Array String := Id.run do
  let mut out := #[]
  let mut afterPub := false
  for line in listing.splitOn "\n" do
    if line.startsWith "pub:" then
      afterPub := true
    else if line.startsWith "sub:" then
      afterPub := false
    else if line.startsWith "fpr:" && afterPub then
      afterPub := false
      let fields := line.splitOn ":"
      if h : 9 < fields.length then
        out := out.push (fields[9].toLower)
  return out

/--
The fingerprints a `VALIDSIG` status line reports.

```
VALIDSIG <signing-fpr> <date> <ts> <expire> <ver> <reserved> <algo> <hash> <class> <primary-fpr>
```

The first field is the key that signed — a subkey, usually — and the last is the
primary it belongs to.  gpg is willing to tell us both; most libraries will tell
you a signature is good without telling you which key made it, which is exactly
the gap rule 5 exists to close.
-/
private def parseValidSig (status : String) : Option (String × String) := Id.run do
  for line in status.splitOn "\n" do
    let tag := "[GNUPG:] VALIDSIG "
    if line.startsWith tag then
      let fields := (line.drop tag.length).toString.splitOn " " |>.filter (!·.isEmpty)
      if h : 0 < fields.length then
        let signing := fields[0].toLower
        -- The primary is the last field.  On a signature made by the primary
        -- key itself gpg still repeats it there, so this needs no special case.
        let primary := (fields[fields.length - 1]!).toLower
        return some (signing, primary)
  return none

/-- Run `gpg`, feeding `stdin` in, returning `(exit, stdout, stderr)`. -/
private def run (args : Array String) (stdin : String := "") :
    IO (UInt32 × String × String) := do
  let child ← IO.Process.spawn {
    cmd := "gpg", args, stdin := .piped, stdout := .piped, stderr := .piped }
  let (stdinHandle, child) ← child.takeStdin
  stdinHandle.putStr stdin
  stdinHandle.flush
  -- Closing stdin is what tells gpg the message is complete; `takeStdin`
  -- dropping the handle at the end of this scope is what closes it.
  let stdout ← IO.asTask child.stdout.readToEnd .dedicated
  let stderr ← child.stderr.readToEnd
  let code ← child.wait
  let out ← IO.ofExcept stdout.get
  return (code, out, stderr)

/-- Import an armoured key into a throwaway home, and report its primary. -/
private def importKey (home : System.FilePath) (key : String) :
    IO (Except String String) := do
  let keyPath := home / "key.asc"
  IO.FS.writeFile keyPath key
  let (code, _, err) ← run (isolated home ++ #["--import", keyPath.toString])
  if code != 0 then
    return .error s!"the key could not be read: {err.trimAscii}"
  let (_, listing, _) ← run (isolated home ++ #["--with-colons", "--list-keys"])
  match primaryFingerprintsIn listing with
  | #[] => return .error "the key holds no primary key"
  | fprs =>
    -- More than one primary in what claims to be one key is not a bundle we
    -- have to make sense of: which one signed is then a question the entry has
    -- not answered.  Take the first and let rule 3 decide whether it is the one
    -- the entry named.
    return .ok fprs[0]!

/--
Check a signature, in a keyring that holds nothing but the key it travels with.

The isolation is doing real work.  gpg will only verify against keys it has, so
a signature made by anything outside this entry's own key fails here with "no
public key" — and the `VALIDSIG` line then tells us which subkey did sign and
which primary it hangs off, so the answer is checked rather than assumed.
-/
def verify (bytes signature key : String) : IO Verdict := do
  if contains key "PRIVATE KEY BLOCK" then
    -- §3.4 rule 2.  Worth logging wherever this is called: it is not something
    -- that happens by accident.
    return .bad "gpg" "the entry carries a private key"
  if !contains key "BEGIN PGP PUBLIC KEY BLOCK" then
    return .bad "gpg" "the entry carries no public key"
  IO.FS.withTempDir fun home => do
    match ← importKey home key with
    | .error reason => return .bad "gpg" reason
    | .ok primary =>
      let sigPath := home / "sig.asc"
      IO.FS.writeFile sigPath signature
      let (code, status, err) ←
        run (isolated home ++ #["--status-fd", "1", "--verify", sigPath.toString, "-"]) bytes
      match parseValidSig status with
      | none =>
        let reason := if code == 0 then "gpg reported no VALIDSIG" else err.trimAscii.toString.replace "\n" "; "
        return { ok := false, verifier := "gpg", primaryKey := primary, reason }
      | some (signing, signedUnder) =>
        if code != 0 then
          return { ok := false, verifier := "gpg", primaryKey := primary,
                   signingKey := signing, reason := err.trimAscii.toString.replace "\n" "; " }
        -- §3.4 rule 5.  The isolated keyring already makes a foreign signature
        -- fail, but saying it rather than relying on it is what stops a later
        -- refactor from quietly removing the guarantee.
        if signedUnder != primary then
          return { ok := false, verifier := "gpg", primaryKey := primary, signingKey := signing,
                   reason := s!"signed under {signedUnder}, which is not this key" }
        return { ok := true, verifier := "gpg", signingKey := signing, primaryKey := primary }

/-- The primary fingerprint of an armoured public key, without verifying anything. -/
def fingerprint (key : String) : IO (Except String String) := do
  if contains key "PRIVATE KEY BLOCK" then
    return .error "that is a private key"
  IO.FS.withTempDir fun home => importKey home key

/--
Check a signature against the keys you already have.

Different from `verify` on purpose: this is the CLI's `cert verify`, which
answers "does *my* keyring accept this", and the answer is allowed to depend on
which keys you have imported.  A node must never use it — what a node believes
has to depend on the entry alone, which is what the isolated `verify` above
guarantees.
-/
def verifyLocal (bytes signature : String) : IO (Except String Unit) := do
  IO.FS.withTempDir fun home => do
    let sigPath := home / "sig.asc"
    IO.FS.writeFile sigPath signature
    let (code, _, err) ← run #["--verify", sigPath.toString, "-"] bytes
    if code == 0 then return .ok () else return .error err.trimAscii.toString

/--
Whether `gpg` is here at all.

Checked once, up front, wherever a batch of entries is about to be checked.
Without it a missing `gpg` reports every entry as unreadable, which reads as
"these certificates are bad" — the most misleading answer this code could give,
and about the most alarming.
-/
def available : IO Bool := do
  try
    let (code, _, _) ← run #["--version"]
    return code == 0
  catch _ => return false

/--
Sign bytes with a local secret key.

Not part of `Verifier`: a node verifies and never signs, and the interface it
depends on should say so.  This is for the CLI, which is where a key lives.
-/
def sign (bytes : String) (keyId : String := "") : IO (Except String String) := do
  let args := #["--armor", "--detach-sign", "--output", "-"]
    ++ (if keyId.isEmpty then #[] else #["--local-user", keyId])
  let (code, out, err) ← run args bytes
  if code != 0 then
    return .error s!"gpg failed ({code}): {err.trimAscii}"
  return .ok out

/-- The armoured public half of a key, to travel with what it signed. -/
def exportPublicKey (keyId : String) : IO (Except String String) := do
  let (code, out, _) ← run #["--armor", "--export", keyId]
  if code != 0 || out.trimAscii.toString.isEmpty then
    return .error s!"gpg could not export the public key for `{keyId}`"
  return .ok out

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
def secretFingerprint (keyId : String := "") : IO (Except String String) := do
  let selector := if keyId.isEmpty then #[] else #[keyId]
  let (code, listing, err) ← run (#["--list-secret-keys", "--with-colons"] ++ selector)
  if code != 0 then
    return .error s!"gpg could not list your secret keys: {err.trimAscii}"
  -- A `sec:` record is a secret primary key, and the `fpr:` after it carries
  -- the fingerprint, exactly as `pub:` does for public ones.
  let mut fingerprints : Array String := #[]
  let mut afterSec := false
  for line in listing.splitOn "\n" do
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

end Gpg

/-- Verification through `gpg`: the reference implementation, as a subprocess. -/
def gpgVerifier : Verifier where
  name := "gpg"
  verify := Gpg.verify
  fingerprint := Gpg.fingerprint
  available := Gpg.available

/--
The verifier everything uses unless it was handed another one.

There is one today.  The record exists so that the day there are two, every
verdict already says which one produced it.
-/
def defaultVerifier : Verifier := gpgVerifier

end Trust

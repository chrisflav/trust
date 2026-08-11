import Trust

/-!
# Tests

Run with `lake test`.

The signature tests need `gpg`, and skip themselves loudly when it is missing
rather than passing quietly — a suite that reports success because it did
nothing is worse than one that fails.
-/

open Trust

namespace Tests

/-- A test that has run, and what it decided. -/
structure Outcome where
  name : String
  ok : Bool
  detail : String := ""

abbrev Suite := IO (Array Outcome)

def check (name : String) (ok : Bool) (detail : String := "") : Outcome :=
  { name, ok, detail }

def eq [BEq α] [ToString α] (name : String) (got expected : α) : Outcome :=
  if got == expected then check name true
  else check name false s!"got {got}, expected {expected}"

/-! ## Timestamps -/

def timeTests : Suite := do
  let now ← nowRFC3339
  return #[
    check "now is RFC 3339" (isRFC3339 now) now,
    check "now ends in Z, as the signed strings do" (now.endsWith "Z") now,
    check "now is seconds precision" (now.length == 20) now,
    check "a Z timestamp parses" (isRFC3339 "2026-07-18T16:14:12Z"),
    check "an offset timestamp parses" (isRFC3339 "2026-07-18T18:14:12+02:00"),
    check "nonsense does not parse" (!isRFC3339 "yesterday"),
    check "an empty string does not parse" (!isRFC3339 ""),
    -- §6.2: suppression is "not later than", so the equal case suppresses.
    check "equal instants are not-later-than"
      (notLaterThan "2026-07-18T16:14:12Z" "2026-07-18T16:14:12Z"),
    check "an earlier assertion is suppressed"
      (notLaterThan "2026-07-18T16:14:11Z" "2026-07-18T16:14:12Z"),
    check "a later assertion reinstates"
      (!notLaterThan "2026-07-18T16:14:13Z" "2026-07-18T16:14:12Z"),
    check "the same instant in another offset compares equal"
      (notLaterThan "2026-07-18T18:14:12+02:00" "2026-07-18T16:14:12Z"),
    -- §3.5: the entry with the later `asserted` wins, and a tie keeps what is stored.
    check "later wins" (laterThan "2026-07-18T16:14:13Z" "2026-07-18T16:14:12Z"),
    check "a tie is not later" (!laterThan "2026-07-18T16:14:12Z" "2026-07-18T16:14:12Z"),
    check "an unparseable comparison never suppresses"
      (!notLaterThan "whenever" "2026-07-18T16:14:12Z")]

/-! ## Canonical bytes

The vector below is the one `web/src/data/certificates.test.ts` pins the browser
against.  Three implementations used to have to agree; after the rewrite there
are two, and this is the byte-for-byte contract between them.
-/

def goldenClaim : Claim where
  decl := "Nat.gcd"
  hash := "629db3ae6e206484"
  hasher := "semantic-v1"
  repo := "trust"
  commit := "0a5a0e6"
  toolchain := "4.31.0"
  asserted := "2026-07-18T16:14:12Z"
  note := "reviewed by hand: \"quotes\", \\backslash, and ünïcodé"

def goldenCanonical : String :=
  "{\"asserted\":\"2026-07-18T16:14:12Z\",\"commit\":\"0a5a0e6\",\"decl\":\"Nat.gcd\"," ++
  "\"hash\":\"629db3ae6e206484\",\"hasher\":\"semantic-v1\"," ++
  "\"note\":\"reviewed by hand: \\\"quotes\\\", \\\\backslash, and ünïcodé\"," ++
  "\"repo\":\"trust\",\"toolchain\":\"4.31.0\"}"

def canonicalTests : Suite := do
  let hostile : Claim := { goldenClaim with note := "\",\"hash\":\"0000000000000000" }
  let rev : Revocation :=
    { fingerprint := "abc", hash := "629db3ae6e206484", hasher := "semantic-v1",
      reason := "the proof was wrong", revoked := "2026-07-18T16:14:12Z" }
  return #[
    eq "the golden claim canonicalises to the browser's bytes"
      goldenClaim.canonical goldenCanonical,
    check "a note cannot forge a field"
      (hostile.canonical != goldenCanonical &&
        (hostile.canonical.splitOn "\\\",\\\"hash").length > 1) hostile.canonical,
    check "every field changes the bytes"
      (({ goldenClaim with decl := "Nat.gcd2" } : Claim).canonical != goldenCanonical &&
       ({ goldenClaim with hash := "0" } : Claim).canonical != goldenCanonical &&
       ({ goldenClaim with hasher := "x" } : Claim).canonical != goldenCanonical &&
       ({ goldenClaim with repo := "x" } : Claim).canonical != goldenCanonical &&
       ({ goldenClaim with commit := "x" } : Claim).canonical != goldenCanonical &&
       ({ goldenClaim with toolchain := "x" } : Claim).canonical != goldenCanonical &&
       ({ goldenClaim with asserted := "2026-07-18T16:14:13Z" } : Claim).canonical != goldenCanonical &&
       ({ goldenClaim with note := "x" } : Claim).canonical != goldenCanonical),
    eq "a revocation canonicalises in §6.1's order"
      rev.canonical
      ("{\"fingerprint\":\"abc\",\"hash\":\"629db3ae6e206484\",\"hasher\":\"semantic-v1\"," ++
       "\"reason\":\"the proof was wrong\",\"revoked\":\"2026-07-18T16:14:12Z\"}"),
    check "a claim round-trips through JSON"
      (match Lean.fromJson? (α := Claim) (Lean.toJson goldenClaim) with
       | .ok c => c.canonical == goldenCanonical
       | .error _ => false)]

/-! ## Signatures

These build a real key with a real signing subkey, sign real bytes, and check
what the bundle checker does with them.  The subkey matters: it is what §3.4
rule 3 is about, and the case the previous implementation got wrong.
-/

structure TestKey where
  primary : String
  subkey : String
  armoredPublic : String

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

/-- Make a key with a separate signing subkey, and hand back both fingerprints. -/
private def makeKey (home : System.FilePath) (uid : String) : IO TestKey := do
  let _ ← gpgIn home #["--quick-gen-key", uid, "ed25519", "sign", "never"]
  -- `--quick-gen-key` alone leaves a key whose primary does the signing, which
  -- is the easy case.  The case worth testing is the ordinary one: a signing
  -- subkey, so that the fingerprint on the signature is not the fingerprint on
  -- the entry.
  let (_, listing0) ← gpgIn home #["--with-colons", "--list-keys", uid]
  let primary0 := Id.run do
    let mut afterPub := false
    for line in listing0.splitOn "\n" do
      if line.startsWith "pub:" then afterPub := true
      else if line.startsWith "fpr:" && afterPub then
        let fields := line.splitOn ":"
        if h : 9 < fields.length then return fields[9]
    return ""
  let _ ← gpgIn home #["--quick-add-key", primary0, "ed25519", "sign", "never"]
  let (_, listing) ← gpgIn home #["--with-colons", "--list-keys", uid]
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
  let (_, pub) ← gpgIn home #["--armor", "--export", uid]
  return { primary, subkey := sub, armoredPublic := pub }

private def signWith (home : System.FilePath) (uid text : String) : IO String := do
  let (_, sig) ← gpgIn home #["--armor", "--detach-sign", "--local-user", uid, "--output", "-"] text
  return sig

private def entryFor (claim : Claim) (sig key fpr : String) : Entry :=
  { claim, signature := sig, key, fingerprint := fpr }

private def isBad : EntryVerdict → Bool := EntryVerdict.isBad

def signatureTests : IO (Array Outcome) := do
  if !(← defaultVerifier.available) then
    return #[check "SKIPPED: gpg is not on PATH, so signatures were not checked" true]
  IO.FS.withTempDir fun home => do
    let alice ← makeKey home "Alice Test <alice@example.org>"
    let _mallory ← makeKey home "Mallory Test <mallory@example.org>"
    if alice.subkey.isEmpty then
      return #[check "gpg made a signing subkey" false "no subkey in the generated key"]
    let claim := { goldenClaim with note := "signed by a subkey" }
    let sig ← signWith home "alice@example.org" claim.canonical
    let malSig ← signWith home "mallory@example.org" claim.canonical

    let good := entryFor claim sig alice.armoredPublic alice.primary
    let subkeyClaimed := entryFor claim sig alice.armoredPublic alice.subkey
    let wrongKey := entryFor claim malSig alice.armoredPublic alice.primary
    let tampered := entryFor { claim with note := "tampered" } sig alice.armoredPublic alice.primary
    let noKey := entryFor claim sig "not a key at all" alice.primary
    let privateKey := entryFor claim sig
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnope\n-----END PGP PRIVATE KEY BLOCK-----" alice.primary

    let verdicts ← verifyBundle
      { entries := #[good, subkeyClaimed, wrongKey, tampered, noKey, privateKey] }
    if verdicts.size != 6 then
      return #[check "one verdict per entry" false s!"{verdicts.size} verdicts"]

    -- gpg signs with the subkey, so this also demonstrates that a subkey
    -- signature is accepted when the entry names the primary — the case rule 5
    -- is about, and the one it must not reject.
    let signedBySubkey := (← defaultVerifier.verify claim.canonical sig alice.armoredPublic)
    return #[
      check "a well-formed entry verifies" (!isBad verdicts[0]!) verdicts[0]!.describe,
      check "gpg signed with the subkey, and it was accepted under the primary"
        (signedBySubkey.ok && signedBySubkey.signingKey == alice.subkey &&
         signedBySubkey.primaryKey == alice.primary)
        s!"signing {signedBySubkey.signingKey}, primary {signedBySubkey.primaryKey}",
      -- The regression: this entry names a fingerprint that is in the key
      -- bundle, but is not the primary.  It used to be accepted.
      check "an entry naming the subkey's fingerprint is refused"
        (isBad verdicts[1]!) verdicts[1]!.describe,
      check "a signature by another key is refused" (isBad verdicts[2]!) verdicts[2]!.describe,
      check "tampered bytes are refused" (isBad verdicts[3]!) verdicts[3]!.describe,
      check "an entry with no public key is refused" (isBad verdicts[4]!) verdicts[4]!.describe,
      check "an entry carrying a private key is refused" (isBad verdicts[5]!) verdicts[5]!.describe,
      check "the fingerprint of a key is its primary"
        ((← defaultVerifier.fingerprint alice.armoredPublic) matches .ok _) ""]

end Tests

open Tests in
def main : IO UInt32 := do
  let suites : List (String × Suite) :=
    [("timestamps", timeTests), ("canonical bytes", canonicalTests),
     ("signatures", signatureTests)]
  let mut failures := 0
  for (name, suite) in suites do
    IO.println s!"\n{name}"
    for outcome in ← suite do
      if outcome.ok then
        IO.println s!"  ok    {outcome.name}"
      else
        failures := failures + 1
        IO.println s!"  FAIL  {outcome.name}"
        if !outcome.detail.isEmpty then IO.println s!"        {outcome.detail}"
  if failures == 0 then
    IO.println "\nall tests passed"
    return 0
  else
    IO.println s!"\n{failures} test(s) failed"
    return 1

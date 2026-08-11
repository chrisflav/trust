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
      (!notLaterThan "whenever" "2026-07-18T16:14:12Z"),
    -- Another implementation may write a fraction; we never do, but rule 1 asks
    -- only that it parse.
    check "a fractional second parses" (isRFC3339 "2026-07-18T16:14:12.500Z"),
    check "a fraction orders within the second"
      (laterThan "2026-07-18T16:14:12.500Z" "2026-07-18T16:14:12.250Z"),
    check "a fraction is not later than the next second"
      (notLaterThan "2026-07-18T16:14:12.500Z" "2026-07-18T16:14:13Z"),
    check "a bare second is not later than its own fraction"
      (notLaterThan "2026-07-18T16:14:12Z" "2026-07-18T16:14:12.500Z")]

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

/-! ## §5.4 Addresses

The rule is a whitelist, so the tests that matter are the refusals: every
address class §5.4 names, and the URL shapes that would let one through.
-/

open Std.Net in
def netTests : Suite := do
  let v4 (a b c d : UInt8) : Bool := Net.blockedV4 #v[a, b, c, d]
  let v6 (s : Vector UInt16 8) : Bool := Net.blockedV6 s
  let rejects (url : String) : Bool := (Net.parseUrl url).toOption.isNone
  let normal (url : String) : String := (Net.normalizeUrl url).toOption.getD "<error>"
  -- 169.254.169.254 is the address §5.4 names, so it gets its own line.
  let metadata := v4 169 254 169 254
  let localhost ← Net.check "http://127.0.0.1:8090"
  let localhostAllowed ← Net.check "http://127.0.0.1:8090" { allowPrivate := true }
  let httpsLocal ← Net.check "https://127.0.0.1"
  return #[
    check "credentials are refused" (rejects "https://user:pass@example.org"),
    check "a fragment is refused" (rejects "https://example.org/#x"),
    check "a query is refused" (rejects "https://example.org/?x=1"),
    check "a scheme that is not http(s) is refused" (rejects "ftp://example.org"),
    check "a schemeless URL is refused" (rejects "example.org"),
    check "an empty URL is refused" (rejects ""),
    check "a hostless URL is refused" (rejects "https:///path"),
    check "a plain https URL is read" ((Net.parseUrl "https://example.org").toOption.isSome),
    eq "the default port is dropped" (normal "https://Example.org:443/") "https://example.org",
    eq "a trailing slash is dropped" (normal "https://example.org/") "https://example.org",
    eq "a non-default port is kept" (normal "https://example.org:8443") "https://example.org:8443",
    eq "the host is lower-cased" (normal "https://EXAMPLE.ORG/api") "https://example.org/api",
    check "loopback is refused" (v4 127 0 0 1),
    check "the link-local metadata address is refused" metadata,
    check "10/8 is refused" (v4 10 1 2 3),
    check "172.16/12 is refused" (v4 172 16 0 1),
    check "172.32 is not in 172.16/12" (!v4 172 32 0 1),
    check "192.168/16 is refused" (v4 192 168 1 1),
    check "carrier-grade NAT is refused" (v4 100 64 0 1),
    check "100.63 is not carrier-grade NAT" (!v4 100 63 0 1),
    check "0.0.0.0 is refused" (v4 0 0 0 0),
    check "multicast is refused" (v4 224 0 0 1),
    check "a public address is allowed" (!v4 93 184 216 34),
    check "IPv6 loopback is refused" (v6 #v[0,0,0,0,0,0,0,1]),
    check "IPv6 unspecified is refused" (v6 #v[0,0,0,0,0,0,0,0]),
    check "IPv6 link-local is refused" (v6 #v[0xfe80,0,0,0,0,0,0,1]),
    check "IPv6 unique-local is refused" (v6 #v[0xfd00,0,0,0,0,0,0,1]),
    check "IPv6 multicast is refused" (v6 #v[0xff02,0,0,0,0,0,0,1]),
    -- An IPv4 address in an IPv6 costume is the way past a check that only
    -- looks at one of the two families.
    check "an IPv4-mapped loopback is refused" (v6 #v[0,0,0,0,0,0xffff,0x7f00,0x0001]),
    check "a public IPv6 address is allowed" (!v6 #v[0x2001,0x4860,0x4860,0,0,0,0,0x8888]),
    check "a loopback URL is refused by default"
      (match localhost with | .error _ => true | .ok _ => false)
      (toString (localhost.toOption.map (·.url))),
    check "https does not excuse a private address"
      (match httpsLocal with | .error _ => true | .ok _ => false),
    check "allowPrivate is what local mode turns on"
      (match localhostAllowed with | .ok p => p.address == "127.0.0.1" && p.port == 8090 | .error _ => false)
      (toString (localhostAllowed.toOption.map (·.address)))]

/-! ## The protocol -/

open Federation in
def federationTests : Suite := do
  let c := Cursor.mk 1717171717000 4821
  let claimAt (t : String) : Claim := { goldenClaim with asserted := t }
  let rev (h hasher fpr t : String) : Revocation :=
    { fingerprint := fpr, hash := h, hasher, reason := "", revoked := t }
  let descriptorJson := "{\"protocol\":\"trust/1\",\"url\":\"https://trust.example.org\"," ++
    "\"name\":\"example\",\"software\":\"trust-server/0.2.0\"," ++
    "\"policy\":{\"maxDepth\":2,\"maxEntries\":500,\"autodiscover\":false}," ++
    "\"counts\":{\"certificates\":1200,\"peers\":3}}"
  let parsed := (Lean.Json.parse descriptorJson >>= Lean.fromJson? (α := Descriptor))
  let noProtocol := (Lean.Json.parse "{\"url\":\"https://x.org\"}" >>= Lean.fromJson? (α := Descriptor))
  return #[
    check "a cursor round-trips" (Cursor.parse? c.toString == some c),
    check "a cursor orders by row within a millisecond"
      ((Cursor.mk 1717171717000 4822).after c && !c.after (Cursor.mk 1717171717000 4822)),
    check "a cursor orders by time across milliseconds"
      ((Cursor.mk 1717171717001 0).after c),
    check "a cursor is not after itself" (!c.after c),
    check "a malformed cursor does not parse" ((Cursor.parse? "1717171717").isNone),
    check "a 16-character hash is valid" (validHash "629db3ae6e206484"),
    check "a short hash is not" (!validHash "629db3ae"),
    check "upper case is not a valid hash" (!validHash "629DB3AE6E206484"),
    check "a hash with non-hex is not valid" (!validHash "629db3ae6e20648z"),
    check "a well-formed claim passes" ((wellFormed goldenClaim) matches .ok _),
    check "a claim with a bad hash does not"
      ((wellFormed { goldenClaim with hash := "nope" }) matches .error _),
    check "a claim with an unparseable timestamp does not"
      ((wellFormed { goldenClaim with asserted := "yesterday" }) matches .error _),
    -- §3.5
    check "a later assertion replaces"
      (replaces (claimAt "2026-07-18T16:14:13Z") (claimAt "2026-07-18T16:14:12Z")),
    check "a tie keeps what is stored"
      (!replaces (claimAt "2026-07-18T16:14:12Z") (claimAt "2026-07-18T16:14:12Z")),
    check "an earlier assertion does not replace"
      (!replaces (claimAt "2026-07-18T16:14:11Z") (claimAt "2026-07-18T16:14:12Z")),
    -- §6.2
    check "a withdrawal suppresses an earlier certificate"
      (suppresses (rev goldenClaim.hash goldenClaim.hasher "abc" "2026-07-18T16:14:12Z") "ABC"
        (claimAt "2026-07-18T16:14:11Z")),
    check "a withdrawal suppresses one asserted at the same instant"
      (suppresses (rev goldenClaim.hash goldenClaim.hasher "abc" "2026-07-18T16:14:12Z") "abc"
        (claimAt "2026-07-18T16:14:12Z")),
    check "a later certificate reinstates"
      (!suppresses (rev goldenClaim.hash goldenClaim.hasher "abc" "2026-07-18T16:14:12Z") "abc"
        (claimAt "2026-07-18T16:14:13Z")),
    check "a withdrawal does not cross hashers"
      (!suppresses (rev goldenClaim.hash "other" "abc" "2026-07-18T16:14:12Z") "abc"
        (claimAt "2026-07-18T16:14:11Z")),
    check "a withdrawal does not cross fingerprints"
      (!suppresses (rev goldenClaim.hash goldenClaim.hasher "abc" "2026-07-18T16:14:12Z") "def"
        (claimAt "2026-07-18T16:14:11Z")),
    -- §7.1
    check "a node does not relay to a URL already in the chain"
      (!mayRelayTo #["https://a.org", "https://b.org"] "https://a.org/"),
    check "a node relays to one that is not" (mayRelayTo #["https://a.org"] "https://b.org"),
    check "the chain is bounded"
      (!mayRelayTo (#["1","2","3","4","5","6","7","8"].map (fun n => s!"https://{n}.org")) "https://x.org"),
    eq "depth is clamped to our own maximum, then decremented" (relayDepth 5 2) 1,
    eq "depth 1 relays no further" (relayDepth 1 2) 0,
    eq "depth 0 is local only" (relayDepth 0 2) 0,
    check "via gains our own URL" ((extendVia #["https://a.org"] "https://b.org").size == 2),
    check "via does not gain it twice"
      ((extendVia #["https://a.org"] "https://a.org").size == 1),
    -- §2
    check "a descriptor parses"
      (match parsed with
       | .ok d => d.recognised && d.url == "https://trust.example.org" &&
                  d.policy.maxEntries == 500 && d.certificates == 1200
       | .error _ => false),
    check "a descriptor without a protocol is fatal" (noProtocol matches .error _)]

/-! ## §3.4, against real signatures -/

open Federation in
def acceptanceTests : IO (Array Outcome) := do
  if !(← defaultVerifier.available) then
    return #[check "SKIPPED: gpg is not on PATH, so acceptance was not checked" true]
  IO.FS.withTempDir fun home => do
    let alice ← makeKey home "Alice Accept <alice@example.org>"
    let mallory ← makeKey home "Mallory Accept <mallory@example.org>"
    let claim := { goldenClaim with note := "accepted" }
    let sig ← signWith home "alice@example.org" claim.canonical
    let good := entryFor claim sig alice.armoredPublic alice.primary
    let subkeyNamed := entryFor claim sig alice.armoredPublic alice.subkey
    let badHash := entryFor { claim with hash := "nope" } sig alice.armoredPublic alice.primary
    let badTime := entryFor { claim with asserted := "yesterday" } sig alice.armoredPublic alice.primary
    let privateKey := entryFor claim sig
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----" alice.primary

    let revocation : Revocation :=
      { fingerprint := alice.primary, hash := claim.hash, hasher := claim.hasher,
        reason := "the proof was wrong", revoked := "2026-07-18T16:14:12Z" }
    let revSig ← signWith home "alice@example.org" revocation.canonical
    let signedRev : SignedRevocation :=
      { revocation, signature := revSig, key := alice.armoredPublic, fingerprint := alice.primary }
    -- A withdrawal of somebody else's assertion, signed by the wrong key.
    let forgedRev : SignedRevocation :=
      { revocation := { revocation with fingerprint := alice.primary },
        signature := ← signWith home "mallory@example.org" revocation.canonical,
        key := mallory.armoredPublic, fingerprint := mallory.primary }

    let (report, kept, keptRevs) ← checkBundle
      { entries := #[good, subkeyNamed, badHash, badTime, privateKey],
        revocations := #[signedRev, forgedRev] }
    return #[
      check "a well-formed entry is accepted" ((← acceptEntry good) matches .ok _),
      check "an entry naming a subkey is a fingerprint mismatch"
        ((← acceptEntry subkeyNamed) matches .error (.fingerprintMismatch _ _)),
      check "a bad hash is malformed, before any crypto runs"
        ((← acceptEntry badHash) matches .error (.malformed _)),
      check "an unparseable timestamp is malformed"
        ((← acceptEntry badTime) matches .error (.malformed _)),
      check "a private key block is refused as such"
        ((← acceptEntry privateKey) matches .error .privateKey),
      check "a signed withdrawal is accepted" ((← acceptRevocation signedRev) matches .ok _),
      check "a withdrawal signed by another key is refused"
        ((← acceptRevocation forgedRev) matches .error _),
      eq "the bundle report counts what it kept" (report.accepted, kept.size) (1, 1),
      eq "and what it refused" report.rejected 5,
      eq "and the withdrawals that survived" (report.revocations, keptRevs.size) (1, 1),
      check "every refusal has a reason" (report.reasons.size == 5)]

end Tests

open Tests in
def main : IO UInt32 := do
  let suites : List (String × Suite) :=
    [("timestamps", timeTests), ("canonical bytes", canonicalTests),
     ("addresses (§5.4)", netTests), ("the protocol", federationTests),
     ("acceptance (§3.4, §6)", acceptanceTests),
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

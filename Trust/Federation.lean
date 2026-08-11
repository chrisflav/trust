import Trust.Cert
import Trust.Pgp
import Trust.Time
import Trust.Net

/-!
# The federation protocol

`FEDERATION.md`, as code.  It lives in the core library rather than in the
server because a node and the CLI have to apply the same rules: `README.md`
says `trust cert verify-bundle` "repeats, locally, precisely the check the
server claims to have done", and the only way for that sentence to stay true is
for both to call this.

What is here is the part that is a *decision* — whether to believe an entry,
whether a withdrawal suppresses a certificate, which of two entries wins.  Where
those decisions are stored, and how a request travels, belongs to the node.
-/

namespace Trust

namespace Federation

/-- The version this implementation speaks.  §2: absence is fatal, mismatch is fatal. -/
def protocolVersion : String := "trust/1"

/-! ## §2 Node descriptor -/

/-- What a node publishes about itself. -/
structure Policy where
  maxDepth : Nat := 2
  maxEntries : Nat := 500
  autodiscover : Bool := false
  deriving Inhabited, Repr

/-- §2's node descriptor. -/
structure Descriptor where
  protocol : String := protocolVersion
  /-- The node's own canonical, externally reachable base URL. -/
  url : String := ""
  name : String := ""
  software : String := ""
  policy : Policy := {}
  certificates : Nat := 0
  peers : Nat := 0
  deriving Inhabited, Repr

open Lean in
instance : ToJson Descriptor where
  toJson d := Json.mkObj [
    ("protocol", d.protocol), ("url", d.url), ("name", d.name), ("software", d.software),
    ("policy", Json.mkObj [
      ("maxDepth", toJson d.policy.maxDepth), ("maxEntries", toJson d.policy.maxEntries),
      ("autodiscover", toJson d.policy.autodiscover)]),
    ("counts", Json.mkObj [
      ("certificates", toJson d.certificates), ("peers", toJson d.peers)])]

open Lean in
instance : FromJson Descriptor where
  fromJson? j := do
    let str (k : String) : String := (j.getObjValAs? String k).toOption.getD ""
    let policy : Policy :=
      match j.getObjVal? "policy" with
      | .ok p => {
          maxDepth := (p.getObjValAs? Nat "maxDepth").toOption.getD 2,
          maxEntries := (p.getObjValAs? Nat "maxEntries").toOption.getD 500,
          autodiscover := (p.getObjValAs? Bool "autodiscover").toOption.getD false }
      | .error _ => {}
    let counts := (j.getObjVal? "counts").toOption.getD (Json.mkObj [])
    return {
      -- The one field whose absence is fatal: a receiver that does not
      -- recognise the version must not proceed, and cannot recognise one that
      -- is not there.
      protocol := ← j.getObjValAs? String "protocol"
      url := str "url", name := str "name", software := str "software", policy
      certificates := (counts.getObjValAs? Nat "certificates").toOption.getD 0
      peers := (counts.getObjValAs? Nat "peers").toOption.getD 0 }

/-- Whether a descriptor is one this node may proceed against (§2). -/
def Descriptor.recognised (d : Descriptor) : Bool := d.protocol == protocolVersion

/-! ## §5.1 Peer states -/

/-- §5.1.  `candidate` is recorded and never queried; `blocked` is never re-admitted. -/
inductive PeerState where
  | seed | active | candidate | blocked
  deriving Inhabited, Repr, BEq, DecidableEq

def PeerState.toString : PeerState → String
  | .seed => "seed" | .active => "active" | .candidate => "candidate" | .blocked => "blocked"

def PeerState.ofString? : String → Option PeerState
  | "seed" => some .seed | "active" => some .active
  | "candidate" => some .candidate | "blocked" => some .blocked
  | _ => none

/-- Whether a node in this state is one we ask questions of. -/
def PeerState.queried : PeerState → Bool
  | .seed | .active => true
  | .candidate | .blocked => false

/-- §5.3: a node lists only the peers it queries itself. -/
def PeerState.published : PeerState → Bool := PeerState.queried

/-! ## §4.3 Cursors -/

/--
A cursor: `<epoch-milliseconds>.<row-id>`.

The row id breaks ties so that a resume never skips an entry written in the same
millisecond as the one before it — which is the case that happens exactly when a
node is busiest.  Opaque to the receiver, ordered by the sender's own clock.
-/
structure Cursor where
  millis : Int
  row : Nat
  deriving Inhabited, Repr, BEq

def Cursor.toString (c : Cursor) : String := s!"{c.millis}.{c.row}"

def Cursor.parse? (s : String) : Option Cursor :=
  match s.splitOn "." with
  | [ms, row] => do
    let millis ← ms.toInt?
    let row ← row.toNat?
    return { millis, row }
  | _ => none

/-- Strictly after, which is what `since` means: a resume must not repeat. -/
def Cursor.after (c prev : Cursor) : Bool :=
  c.millis > prev.millis || (c.millis == prev.millis && c.row > prev.row)

instance : LT Cursor where
  lt a b := b.after a

/-! ## §3.4 Acceptance -/

/-- Why an entry was refused, in the sender's terms rather than ours. -/
inductive Rejection where
  | malformed (why : String)
  | privateKey
  | fingerprintMismatch (claimed actual : String)
  | badSignature (why : String)
  deriving Inhabited, Repr

def Rejection.describe : Rejection → String
  | .malformed why => why
  | .privateKey => "the entry carries a private key"
  | .fingerprintMismatch claimed actual =>
    s!"the entry claims {claimed}, but the key it travels with is {actual}"
  | .badSignature why => why

/-- §3.4 rule 1: a hash is lower-case hex, 16 to 128 characters. -/
def validHash (h : String) : Bool :=
  h.length ≥ 16 && h.length ≤ 128 &&
    h.all fun c => ('0' ≤ c && c ≤ '9') || ('a' ≤ c && c ≤ 'f')

/--
§3.4 rule 1, as far as it can be checked without crypto.

The eight fields are present by construction — a claim that lost one would not
have parsed — so what is left is the shape of `hash` and whether `asserted` is a
timestamp at all.
-/
def wellFormed (claim : Claim) : Except String Unit := do
  if claim.decl.isEmpty then throw "claim.decl is empty"
  if !validHash claim.hash then
    throw s!"claim.hash is not lower-case hex of 16-128 characters: {claim.hash}"
  if claim.hasher.isEmpty then throw "claim.hasher is empty"
  if !isRFC3339 claim.asserted then
    throw s!"claim.asserted is not a timestamp: {claim.asserted}"
  return ()

/--
Everything §3.4 requires, in one place.

The order is chosen so that the reason a receiver reports is the most specific
true one: shape before crypto, and the key before the signature.  A caller
**must** discard — never store, never relay — an entry this refuses.
-/
def acceptEntry (entry : Entry) (verifier : Verifier := defaultVerifier) :
    IO (Except Rejection Unit) := do
  match wellFormed entry.claim with
  | .error why => return .error (.malformed why)
  | .ok _ =>
    if entry.fingerprint.isEmpty then
      return .error (.malformed "the entry names no fingerprint")
    -- Rules 2, 4 and 5 are what the verifier answers; rule 3 is ours, because
    -- it compares the key against what the *entry* said, which the verifier
    -- never sees.
    let verdict ← verifier.verify entry.claim.canonical entry.signature entry.key
    if !verdict.ok then
      if verdict.reason == "the entry carries a private key" then
        return .error .privateKey
      return .error (.badSignature verdict.reason)
    if entry.fingerprint.toLower != verdict.primaryKey then
      return .error (.fingerprintMismatch entry.fingerprint.toLower verdict.primaryKey)
    return .ok ()

/-- §6.1 and §6.2 rule 1: a revocation is signed by the key whose assertion it withdraws. -/
def acceptRevocation (signed : SignedRevocation) (verifier : Verifier := defaultVerifier) :
    IO (Except Rejection Unit) := do
  if !validHash signed.revocation.hash then
    return .error (.malformed "revocation.hash is not lower-case hex of 16-128 characters")
  if !isRFC3339 signed.revocation.revoked then
    return .error (.malformed "revocation.revoked is not a timestamp")
  let verdict ← verifier.verify signed.revocation.canonical signed.signature signed.key
  if !verdict.ok then
    if verdict.reason == "the entry carries a private key" then
      return .error .privateKey
    return .error (.badSignature verdict.reason)
  -- The withdrawal has to be signed by the key it names, or anyone could
  -- withdraw anyone's assertion by signing a message about it.
  if signed.revocation.fingerprint.toLower != verdict.primaryKey then
    return .error (.fingerprintMismatch signed.revocation.fingerprint.toLower verdict.primaryKey)
  if signed.fingerprint.toLower != verdict.primaryKey then
    return .error (.fingerprintMismatch signed.fingerprint.toLower verdict.primaryKey)
  return .ok ()

/-! ## §3.5 Identity and replacement -/

/-- §3.5: an entry's identity is the triple.  Hashers are never comparable, so it is a triple. -/
structure Identity where
  fingerprint : String
  hash : String
  hasher : String
  deriving Inhabited, Repr, BEq, Hashable, DecidableEq

def identityOfEntry (e : Entry) : Identity :=
  { fingerprint := e.fingerprint.toLower, hash := e.claim.hash, hasher := e.claim.hasher }

def identityOfRevocation (r : Revocation) : Identity :=
  { fingerprint := r.fingerprint.toLower, hash := r.hash, hasher := r.hasher }

/--
§3.5: on collision the later `asserted` wins, and a tie keeps what is stored.

The tie rule is what makes repeatedly gossiping the same set converge instead of
oscillating, so it is not an arbitrary choice between two equal options.
-/
def replaces (incoming stored : Claim) : Bool :=
  laterThan incoming.asserted stored.asserted

/-! ## §6.2 Suppression -/

/--
Whether `revocation` suppresses `claim`.

"Not later than", so a certificate asserted at the same instant as the
withdrawal is suppressed and one asserted later reinstates — which is why
re-issuing after a withdrawal is ordinary and needs no second message.
-/
def suppresses (revocation : Revocation) (fingerprint : String) (claim : Claim) : Bool :=
  identityOfRevocation revocation == ({ fingerprint := fingerprint.toLower, hash := claim.hash, hasher := claim.hasher } : Identity)
    && notLaterThan claim.asserted revocation.revoked

/-! ## §7.1 Relay chains -/

/--
Whether this node may relay to `url`, given the chain so far.

A TTL alone does not stop a cycle multiplying a request, so §7.1 carries the
URLs already in the chain and forbids relaying to one of them.  A node that
finds itself in `via` answers locally.
-/
def mayRelayTo (via : Array String) (url : String) (maxViaLength : Nat := 8) : Bool :=
  via.size < maxViaLength && !via.any (fun u =>
    match Net.normalizeUrl u, Net.normalizeUrl url with
    | .ok a, .ok b => a == b
    | _, _ => u == url)

/-- §7.1: a node clamps the depth it was handed to its own maximum, then relays one less. -/
def relayDepth (received : Nat) (maxDepth : Nat) : Nat :=
  let clamped := min received maxDepth
  if clamped == 0 then 0 else clamped - 1

/-- §7.1: append our own URL before relaying, so the next hop can do the same. -/
def extendVia (via : Array String) (own : String) : Array String :=
  if via.contains own then via else via.push own

/-! ## Bundles -/

/--
What a check of a whole bundle found.

Rejections are reported rather than swallowed (§4.2): a node that silently drops
entries is indistinguishable from one that is broken.
-/
structure ImportReport where
  accepted : Nat := 0
  rejected : Nat := 0
  revocations : Nat := 0
  reasons : Array String := #[]
  deriving Inhabited, Repr

/--
Apply §3.4 to every entry and §6 to every revocation, and say what survived.

This performs no storage: it is the decision, and the caller keeps what it is
told to keep.  That is what lets the CLI use it to check a bundle it will never
store and the server use it to decide what to write.
-/
def checkBundle (bundle : Bundle) (verifier : Verifier := defaultVerifier) :
    IO (ImportReport × Array Entry × Array SignedRevocation) := do
  let mut report : ImportReport := {}
  let mut entries := #[]
  let mut revocations := #[]
  for entry in bundle.entries do
    match ← acceptEntry entry verifier with
    | .ok _ => entries := entries.push entry; report := { report with accepted := report.accepted + 1 }
    | .error r =>
      report := { report with rejected := report.rejected + 1 }
      report := { report with reasons := report.reasons.push r.describe }
  for revocation in bundle.revocations do
    match ← acceptRevocation revocation verifier with
    | .ok _ =>
      revocations := revocations.push revocation
      report := { report with revocations := report.revocations + 1 }
    | .error r =>
      report := { report with rejected := report.rejected + 1 }
      report := { report with reasons := report.reasons.push r.describe }
  return (report, entries, revocations)

end Federation

end Trust

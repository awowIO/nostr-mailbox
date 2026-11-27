// The page's protocol engine under Node, for tests/test_web_ui.py.
//
// argv[2] is the engine script, lifted verbatim out of web/index.html by the test. One
// JSON request arrives on stdin and one JSON answer leaves on stdout; a failure is a
// stack trace on stderr and exit 1. Nothing here re-implements the protocol: every call
// goes to `globalThis.NM`, the same object the browser tab uses. Every relay wait inside
// it is bounded by the timeout the test passes; nothing else in it waits.
import fs from 'node:fs';

new Function(fs.readFileSync(process.argv[2], 'utf8'))();
const NM = globalThis.NM;
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const h = NM.unhex, x = NM.hex, u = NM.utf8;

function crypto(c) {
  return {
    sha256: c.sha256.map((m) => x(NM.sha256(h(m)))),
    hmac: c.hmac.map(([k, m]) => x(NM.hmacSha256(h(k), h(m)))),
    hkdf: c.hkdf.map(([salt, ikm, info, n]) => x(NM.hkdfExpand(NM.hkdfExtract(h(salt), h(ikm)), h(info), n))),
    chacha: c.chacha.map(([k, n, d]) => x(NM.chacha20(h(k), h(n), h(d)))),
    pubkey: c.pubkey.map((sk) => x(NM.getPublicKey(h(sk)))),
    sign: c.sign.map(([sk, msg, aux]) => x(NM.schnorrSign(h(msg), h(sk), h(aux)))),
    verify: c.verify.map(([pk, msg, sig]) => NM.schnorrVerify(h(msg), h(pk), h(sig))),
    ecdh: c.ecdh.map(([sk, pk]) => x(NM.ecdhX(h(sk), h(pk)))),
    conv: c.conv.map(([sk, pk]) => x(NM.conversationKey(h(sk), h(pk)))),
    campaign: c.campaign.map(([key, name]) => x(NM.campaignConversationKey(h(key), name))),
    padded: c.padded.map((n) => NM.calcPaddedLen(n)),
    encrypt: c.encrypt.map(([ck, nonce, plain]) => NM.nip44EncryptBytes(h(plain), h(ck), h(nonce))),
    decrypt: c.decrypt.map(([ck, payload]) => x(NM.nip44DecryptBytes(payload, h(ck)))),
    tampered: c.tampered.map(([ck, payload]) => { try { NM.nip44DecryptBytes(payload, h(ck)); return 'opened'; } catch (e) { return e.message; } }),
    npub: c.npub.map((pk) => NM.npub(pk)),
    nsec: c.nsec.map((sk) => NM.nsec(h(sk))),
    bech_back: c.bech_back.map((s) => x(NM.bech32Decode(s.slice(0, 4), s))),
    event_id: c.event_id.map((e) => NM.eventId(e)),
    verify_event: c.verify_event.map((e) => { try { NM.verifyEvent(e); return 'ok'; } catch (err) { return err.message; } }),
  };
}

function records(c) {
  const trust = NM.makeTrust(c.trust);
  const scope = NM.rootScope(trust);
  return {
    content_keys: c.content_keys.map((parts) => NM.contentKey(...parts)),
    toml: NM.trustToml(c.toml),
    handoff: NM.renderHandoff(NM.conditionHandoff(c.condition), c.provenance),
    after: NM.conditionAfter(c.condition, c.claim, c.decision, c.decision_id),
    encoded: NM.encodeRecord(scope, 'message', c.payload),
    decoded: c.python_events.map((ev) => { const r = NM.decodeRecord(scope, NM.verifyEvent(ev), ev.kind, 'message', 'bus'); return r.payload; }),
    token: (() => { const t = NM.decodeInviteToken(c.token); return { code: t.code, member: t.member, relay: t.trust.relay, campaign: t.trust.campaign, operators: t.trust.operator_pubkeys, campaign_key: t.trust.campaign_key }; })(),
    topic_token: (() => { const t = NM.decodeInviteToken(c.topic_token); return { code: t.code, member: t.member, group: t.trust.group, keyring: t.trust.keyring, campaign_key: t.trust.campaign_key, extras: t.extras }; })(),
    constants: NM.C, kinds: NM.KIND,
  };
}

function summarize(id, scope, view) {
  const base = { id, kind: scope.kind, epochs: [...new Set(scope.epochs.map((e) => e.n))].sort((a, b) => a - b), current: scope.current,
    members: scope.roster ? [...scope.roster.members].sort() : null, admins: [...scope.admins].sort(),
    requests: (scope.requests || []).map((r) => ({ id: r.id, pubkey: r.pubkey, reason: r.reason })) };
  if (!view) return { ...base, nokey: true };
  const topics = {};
  for (const [t, tv] of Object.entries(view.topics)) {
    topics[t] = { sealed: tv.sealed,
      messages: tv.messages.map((m) => ({ id: m.id, author: m.author, body: m.body, kind: m.kind, epoch: m.epoch, refs: m.refs, released: !!m.released })),
      acks: tv.acks.map((a) => ({ msg_id: a.msg_id, seat: a.seat, disposition: a.disposition, author: a.author, result_ref: a.result_ref || null, epoch: a.epoch })) };
  }
  const tri = NM.triage(view);
  return { ...base, topics,
    quarantine: view.quarantine.map((q) => ({ id: q.id, body: q.body, why: q.why, epoch: q.epoch, ruling: q.ruling ? q.ruling.disposition : null })),
    conditions: [...view.heads.values()].map((c) => ({ condition: c.condition, rev: c.rev, state: c.state, evidence: c.evidence, handoff: NM.renderHandoff(NM.conditionHandoff(c)) })),
    claims: view.claims.map((c) => ({ id: c.id, condition: c.condition, effect: c.effect, epoch: c.epoch, author: c.author })),
    decisions: view.decisions.map((d) => ({ claim: d.claim, outcome: d.outcome, author: d.author })),
    handoffs: view.handoffs.map((p) => ({ next_action: p.next_action, for_seat: p.for_seat })),
    directives: view.ledger.inForce.map((d) => d.text), operator_md: view.operatorMd,
    triage: Object.fromEntries(Object.entries(tri.targets).map(([k, v]) => [k, { count: v.count, compaction_due: v.compaction_due }])),
    rejected: view.rejected.map((r) => ({ id: r.id, reason: r.reason, code: r.code || '' })) };
}

async function session(c) {
  const trust = NM.makeTrust(c.trust);
  const signer = c.bridge ? new NM.BridgeSigner(c.bridge.base, c.bridge.token) : new NM.KeySigner(h(c.secret));
  const relay = new NM.RelayClient(trust.relay, signer, { authUrl: trust.relay_auth_url || trust.relay, timeoutS: c.timeout_s });
  await relay.connect();
  const desk = new NM.Desk(trust, signer, relay);
  const result = { me: relay.pubkey, ops: [] };
  if (c.join) result.joined = await relay.join(c.join);
  const load = async () => {
    const { keyrings, rejected } = await desk.inbox();
    const L = { keyrings, wrapsRejected: rejected, scopes: {}, views: {} };
    if (c.root) { const root = NM.rootScope(trust); L.scopes[''] = root; L.views[''] = NM.buildView(root, await desk.scopeEvents(root)); }
    for (const id of c.topics || []) {
      const evs = await relay.queryAll({ '#h': [id] });
      const scope = NM.topicScope(trust, id, evs, keyrings, relay.pubkey);
      L.scopes[id] = scope;
      if (scope.epochs.length) L.views[id] = NM.buildView(scope, evs);
    }
    return L;
  };
  let L = await load();
  const run = {
    post: (o) => desk.post(L.scopes[o.scope], o.topic, { body: o.body, kind: o.kind || 'message', subject: o.subject || '', refs: o.refs || [], reply_to: o.reply_to || null }, o.key),
    post_in_epoch: (o) => desk.post({ ...L.scopes[o.scope], current: o.epoch }, o.topic, { body: o.body, kind: o.kind || 'message', subject: '', refs: [], reply_to: null }),
    ack: (o) => desk.ack(L.scopes[o.scope], L.views[o.scope], o.topic, o.seat, o.msg, { disposition: o.disposition, result_ref: o.result_ref || null, note: o.note || null }),
    todo: (o) => desk.todo(L.scopes[o.scope], L.views[o.scope], o.note, { target: o.target }),
    create: (o) => desk.createTopic(o.topic, o.name),
    grant: (o) => desk.grant(L.scopes[o.scope], o.member, o.mode),
    revoke: (o) => desk.revoke(L.scopes[o.scope], o.member),
    request: (o) => desk.requestAccess(o.topic, o.reason, o.code || null),
    decline: (o) => desk.decline(L.scopes[o.scope], o.request),
    gate: (o) => desk.gate(L.scopes[o.scope], L.views[o.scope], o.topic, o.msg, o.approve),
    open_condition: (o) => desk.openCondition(L.scopes[o.scope], L.views[o.scope], o.condition),
    claim: (o) => desk.claim(L.scopes[o.scope], o.claim),
    decide: (o) => desk.decide(L.scopes[o.scope], L.views[o.scope], o.claim, o.ruling),
    profile: (o) => desk.profile(o.handle),
    mail_grant: (o) => desk.grantMail(o.peer, { trust: o.trust || 'human_gated', parts: o.parts || ['inbox'] }),
    mail_revoke: (o) => desk.revokeMail(o.peer),
    mail: (o) => desk.sendMail({ owner: o.owner, part: o.part || 'inbox', subject: o.subject, body: o.body }),
    mail_gate: async (o) => desk.gateMail(L.scopes[''], L.views[''], o.msg, o.approve),
    receipt: async (o) => { const mb = await desk.mailbox(L.views[''] || null); const m = mb.items.find((i) => i.id === o.msg); const ev = await NM.buildReceipt(signer, m.outer, { status: o.status, note: o.note, campaign: trust.campaign }); await relay.publish(ev); return ev.id; },
    reply: async (o) => { const mb = await desk.mailbox(L.views[''] || null); const m = mb.items.find((i) => i.id === o.msg); const ev = await NM.buildMail(signer, { owner: m.owner, reader: m.outgoing ? m.to : m.from, part: m.part, campaign: trust.campaign, body: o.body, inReplyTo: m.outer }); await relay.publish(ev); return ev.id; },
  };
  for (const op of c.ops || []) {
    let got;
    try { got = { ok: await run[op.op](op) }; } catch (e) { if (!(e instanceof NM.NMError)) throw e; got = { error: e.message, code: e.code }; }
    result.ops.push(got);
    L = await load();
  }
  result.keyrings = L.keyrings.map((k) => ({ topic: k.topic, epochs: k.epochs.map((e) => e.n), granter: k.granter, mode: k.mode, wrap: k.wrap }));
  result.wraps_rejected = L.wrapsRejected;
  result.scopes = Object.fromEntries(Object.entries(L.scopes).map(([id, s]) => [id, summarize(id, s, L.views[id])]));
  if (c.mailbox) {
    const mb = await desk.mailbox(L.views[''] || null);
    const strip = (m) => ({ id: m.id, from: m.from, to: m.to, owner: m.owner, part: m.part, thread: m.thread, msg: m.msg, reply_to: m.reply_to, outgoing: m.outgoing, body: m.body || null, granted: m.granted, why: m.why || null, ruling: m.ruling ? m.ruling.disposition : null, released: !!m.released });
    result.mailbox = { items: mb.items.map(strip), held: mb.held.map(strip), receipts: mb.receipts.map(strip), rejected: mb.rejected, grants: [...mb.grants.values()].map((g) => ({ peer: g.peer, active: g.active, trust: g.trust, scope: g.scope, parts: g.parts })) };
  }
  result.notices = relay.notices;
  relay.close();
  return result;
}

async function mailPrimitives(c) {
  // open envelopes made in Python, and make one for Python to open
  const signer = new NM.KeySigner(h(c.secret));
  const opened = [];
  for (const ev of c.envelopes) {
    try { const m = await NM.openMail(signer, ev); opened.push({ ok: true, body: m.body, signed_by: m.signedBy, thread: NM.firstTag(m.outer, 'thread') }); }
    catch (e) { opened.push({ ok: false, error: e.message }); }
  }
  const made = await NM.buildMail(signer, { owner: c.owner, reader: c.owner, part: 'inbox', campaign: c.campaign, subject: 'from the page', body: c.body });
  return { opened, made, commit: NM.threadCommit(c.commit.owner, c.commit.opener, c.commit.nonce, c.commit.part) };
}

const scenarios = { crypto, records, session, mail: mailPrimitives };
const answer = await scenarios[input.scenario](input);
// exit only once the answer is flushed: a pipe write is asynchronous in Node, and the
// open WebSocket handles would otherwise keep the process alive
process.stdout.write(JSON.stringify(answer), () => process.exit(0));

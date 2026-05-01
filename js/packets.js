// ブラウザ内パケットビルダ。Node サーバ版 (server/packets/) と同等のロジックを
// Uint8Array ベースで再実装したもの。サーバ不要で動く。
//
// 公開: window.RouterPackets = { buildPacket(spec) -> Uint8Array }
// 入力 spec のキーはサーバ版と互換:
//   { proto, src, dst, srcMac?, dstMac?, ... }
(function (global) {
  // ---------- 低レベル ----------
  function checksum16(view, start, end) {
    let sum = 0, i = start;
    for (; i + 1 < end; i += 2) sum += (view[i] << 8) | view[i + 1];
    if (i < end) sum += view[i] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
  }
  function ipToBytes(ip) {
    const p = String(ip).split('.').map(n => parseInt(n, 10));
    if (p.length !== 4 || p.some(n => isNaN(n) || n < 0 || n > 255)) {
      throw new Error('Bad IP: ' + ip);
    }
    return Uint8Array.from(p);
  }
  function macToBytes(mac) {
    const p = String(mac).split(':').map(s => parseInt(s, 16));
    if (p.length !== 6 || p.some(n => isNaN(n) || n < 0 || n > 255)) {
      throw new Error('Bad MAC: ' + mac);
    }
    return Uint8Array.from(p);
  }
  function macFromId(id) {
    let h = 2166136261 >>> 0;
    for (const ch of String(id)) {
      h ^= ch.charCodeAt(0);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return Uint8Array.from([0x02, (h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff, 0x01]);
  }
  function strToBytes(s) {
    if (s == null) return new Uint8Array(0);
    if (s instanceof Uint8Array) return s;
    return new TextEncoder().encode(String(s));
  }
  function concat(parts) {
    let n = 0; parts.forEach(p => n += p.length);
    const out = new Uint8Array(n);
    let off = 0;
    parts.forEach(p => { out.set(p, off); off += p.length; });
    return out;
  }
  function w16(buf, off, v) { buf[off] = (v >> 8) & 0xff; buf[off + 1] = v & 0xff; }
  function w32(buf, off, v) {
    buf[off] = (v >>> 24) & 0xff; buf[off + 1] = (v >>> 16) & 0xff;
    buf[off + 2] = (v >>> 8) & 0xff; buf[off + 3] = v & 0xff;
  }

  // ---------- L2/L3/L4 ----------
  function buildEthernet(dstMac, srcMac, ethertype, payload) {
    const buf = new Uint8Array(14 + payload.length);
    buf.set(dstMac, 0);
    buf.set(srcMac, 6);
    w16(buf, 12, ethertype);
    buf.set(payload, 14);
    return buf;
  }

  let nextIpId = 1;
  function buildIPv4(srcIp, dstIp, proto, payload, ttl) {
    const total = 20 + payload.length;
    const buf = new Uint8Array(total);
    buf[0] = 0x45;
    buf[1] = 0;
    w16(buf, 2, total);
    w16(buf, 4, (nextIpId++) & 0xffff);
    w16(buf, 6, 0x4000);
    buf[8] = ttl || 64;
    buf[9] = proto;
    w16(buf, 10, 0);
    buf.set(ipToBytes(srcIp), 12);
    buf.set(ipToBytes(dstIp), 16);
    w16(buf, 10, checksum16(buf, 0, 20));
    buf.set(payload, 20);
    return buf;
  }

  function buildICMPEcho(id, seq, data) {
    const buf = new Uint8Array(8 + data.length);
    buf[0] = 8; buf[1] = 0;
    w16(buf, 2, 0);
    w16(buf, 4, id & 0xffff);
    w16(buf, 6, seq & 0xffff);
    buf.set(data, 8);
    w16(buf, 2, checksum16(buf, 0, buf.length));
    return buf;
  }

  function buildUDP(sport, dport, payload) {
    const buf = new Uint8Array(8 + payload.length);
    w16(buf, 0, sport); w16(buf, 2, dport);
    w16(buf, 4, 8 + payload.length); w16(buf, 6, 0);
    buf.set(payload, 8);
    return buf;
  }

  function buildTCP(srcIp, dstIp, sport, dport, flags, payload, seq, ack) {
    const tcpLen = 20 + payload.length;
    const buf = new Uint8Array(tcpLen);
    w16(buf, 0, sport); w16(buf, 2, dport);
    w32(buf, 4, (seq || 1) >>> 0);
    w32(buf, 8, (ack || 0) >>> 0);
    buf[12] = (5 << 4); buf[13] = flags & 0xff;
    w16(buf, 14, 65535); w16(buf, 16, 0); w16(buf, 18, 0);
    buf.set(payload, 20);

    const pseudo = new Uint8Array(12);
    pseudo.set(ipToBytes(srcIp), 0);
    pseudo.set(ipToBytes(dstIp), 4);
    pseudo[8] = 0; pseudo[9] = 6;
    w16(pseudo, 10, tcpLen);
    const all = concat([pseudo, buf]);
    w16(buf, 16, checksum16(all, 0, all.length));
    return buf;
  }

  function buildARP(op, srcMac, srcIp, dstMac, dstIp) {
    const buf = new Uint8Array(28);
    w16(buf, 0, 1); w16(buf, 2, 0x0800);
    buf[4] = 6; buf[5] = 4;
    w16(buf, 6, op);
    buf.set(srcMac, 8);
    buf.set(ipToBytes(srcIp), 14);
    buf.set(dstMac, 18);
    buf.set(ipToBytes(dstIp), 24);
    return buf;
  }

  function buildBGPHeader(type, body) {
    const len = 19 + body.length;
    const buf = new Uint8Array(len);
    buf.fill(0xff, 0, 16);
    w16(buf, 16, len);
    buf[18] = type;
    buf.set(body, 19);
    return buf;
  }
  function buildBGPOpen(myAs, holdTime, bgpId) {
    const body = new Uint8Array(10);
    body[0] = 4;
    w16(body, 1, myAs & 0xffff);
    w16(body, 3, holdTime);
    body.set(ipToBytes(bgpId), 5);
    body[9] = 0;
    return buildBGPHeader(1, body);
  }
  function buildBGPKeepalive() { return buildBGPHeader(4, new Uint8Array(0)); }
  function buildBGPUpdate(spec) {
    const wList = spec.withdrawn || [];
    const wParts = wList.map(r => {
      const oct = Math.ceil(r.prefixLen / 8);
      const b = new Uint8Array(1 + oct);
      b[0] = r.prefixLen;
      const ib = ipToBytes(r.prefix);
      for (let i = 0; i < oct; i++) b[1 + i] = ib[i];
      return b;
    });
    const wBytes = concat(wParts);
    const wLen = new Uint8Array(2); w16(wLen, 0, wBytes.length);

    const nlriList = spec.nlri || [];
    const paParts = [];
    if (nlriList.length > 0) {
      paParts.push(Uint8Array.from([0x40, 1, 1, (spec.origin != null ? spec.origin : 0) & 0xff]));
      const asPath = spec.asPath || [];
      if (asPath.length > 0) {
        const seg = new Uint8Array(2 + asPath.length * 2);
        seg[0] = 2; seg[1] = asPath.length;
        asPath.forEach((as, i) => w16(seg, 2 + i * 2, as & 0xffff));
        paParts.push(concat([Uint8Array.from([0x40, 2, seg.length]), seg]));
      } else {
        paParts.push(Uint8Array.from([0x40, 2, 0]));
      }
      paParts.push(concat([Uint8Array.from([0x40, 3, 4]), ipToBytes(spec.nextHop || '0.0.0.0')]));
    }
    const paBytes = concat(paParts);
    const paLen = new Uint8Array(2); w16(paLen, 0, paBytes.length);

    const nParts = nlriList.map(r => {
      const oct = Math.ceil(r.prefixLen / 8);
      const b = new Uint8Array(1 + oct);
      b[0] = r.prefixLen;
      const ib = ipToBytes(r.prefix);
      for (let i = 0; i < oct; i++) b[1 + i] = ib[i];
      return b;
    });
    return buildBGPHeader(2, concat([wLen, wBytes, paLen, paBytes, ...nParts]));
  }
  function buildBGPNotification(code, sub) {
    return buildBGPHeader(3, Uint8Array.from([code & 0xff, sub & 0xff]));
  }

  function buildOSPFHello(routerId, areaId, mask, helloInt, deadInt, prio) {
    const body = new Uint8Array(20);
    body.set(ipToBytes(mask || '255.255.255.0'), 0);
    w16(body, 4, helloInt || 10);
    body[6] = 0x02;
    body[7] = (prio == null ? 1 : prio) & 0xff;
    w32(body, 8, deadInt || 40);

    const headerLen = 24;
    const buf = new Uint8Array(headerLen + body.length);
    buf[0] = 2; buf[1] = 1;
    w16(buf, 2, headerLen + body.length);
    buf.set(ipToBytes(routerId), 4);
    buf.set(ipToBytes(areaId || '0.0.0.0'), 8);
    w16(buf, 12, 0); w16(buf, 14, 0);
    buf.set(body, headerLen);
    // OSPF checksum: auth field(16..24) を除外
    const tmp = concat([buf.slice(0, 16), buf.slice(24)]);
    w16(buf, 12, checksum16(tmp, 0, tmp.length));
    return buf;
  }

  // ---------- ディスパッチャ ----------
  const BCAST = Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  const ZERO  = new Uint8Array(6);

  // IF ごとの MAC アドレス生成
  // 上位 24 bit: 50:00:00 (固定)
  // 中位 12 bit: routerIdx (トポロジー上の 1-based インスタンス ID)
  // 下位 12 bit: ifaceIdx  (config 内 interface 宣言の 0-based 順番)
  // 例: R1(idx=1), Gi0/0(idx=0) → 5000.0001.0000
  function buildIfaceMac(routerIdx, ifaceIdx) {
    const r = (routerIdx & 0xFFF);
    const i = (ifaceIdx  & 0xFFF);
    return Uint8Array.from([
      0x50, 0x00, 0x00,
      (r >> 4) & 0xFF,
      ((r & 0xF) << 4) | ((i >> 8) & 0xF),
      i & 0xFF,
    ]);
  }

  function buildPacket(spec) {
    const srcMac = spec.srcMac instanceof Uint8Array
      ? spec.srcMac
      : (typeof spec.srcMac === 'string' ? macToBytes(spec.srcMac) : macFromId(spec.routerId || spec.src));
    const dstMac = spec.dstMac instanceof Uint8Array
      ? spec.dstMac
      : (typeof spec.dstMac === 'string'
          ? macToBytes(spec.dstMac)
          : Uint8Array.from([0x02, 0, 0, 0, 0, 0x02]));

    switch ((spec.proto || '').toLowerCase()) {
      case 'icmp': {
        const icmp = buildICMPEcho(spec.id || 1, spec.seq || 1, strToBytes(spec.payload || 'abcdefghij'));
        const ip = buildIPv4(spec.src, spec.dst, 1, icmp, spec.ttl);
        return buildEthernet(dstMac, srcMac, 0x0800, ip);
      }
      case 'udp': {
        const udp = buildUDP(spec.sport || 1024, spec.dport || 1024, strToBytes(spec.payload));
        const ip = buildIPv4(spec.src, spec.dst, 17, udp, spec.ttl);
        return buildEthernet(dstMac, srcMac, 0x0800, ip);
      }
      case 'tcp': {
        const flagsMap = { fin: 1, syn: 2, rst: 4, psh: 8, ack: 16, urg: 32 };
        const flagList = Array.isArray(spec.flags) ? spec.flags : ['syn'];
        let flags = 0;
        flagList.forEach(f => { flags |= flagsMap[String(f).toLowerCase()] || 0; });
        const tcp = buildTCP(spec.src, spec.dst, spec.sport || 1024, spec.dport || 80,
          flags, strToBytes(spec.payload), spec.seq || 1, spec.ack || 0);
        const ip = buildIPv4(spec.src, spec.dst, 6, tcp, spec.ttl);
        return buildEthernet(dstMac, srcMac, 0x0800, ip);
      }
      case 'arp': {
        const op = (spec.op === 'reply' || spec.op === 2) ? 2 : 1;
        // targetMac は Uint8Array または colon 文字列を受け付ける
        const toBytes = m => m instanceof Uint8Array ? m : macToBytes(m);
        const targetMacBytes = spec.targetMac ? toBytes(spec.targetMac) : ZERO;
        const target = (op === 1) ? ZERO   : targetMacBytes;
        const ethDst = (op === 1) ? BCAST  : targetMacBytes;
        const arp = buildARP(op, srcMac, spec.src, target, spec.dst);
        return buildEthernet(ethDst, srcMac, 0x0806, arp);
      }
      case 'bgp': {
        let body;
        const t = (spec.bgpType || 'keepalive').toLowerCase();
        if (t === 'open') body = buildBGPOpen(spec.as || 65000, spec.hold || 180, spec.bgpId || spec.src);
        else if (t === 'notification') body = buildBGPNotification(spec.code || 6, spec.subcode || 0);
        else if (t === 'update') body = buildBGPUpdate(spec);
        else body = buildBGPKeepalive();
        const tcp = buildTCP(spec.src, spec.dst, spec.sport || 50000, spec.dport || 179,
          0x18, body, spec.seq || 1, spec.ack || 1);
        const ip = buildIPv4(spec.src, spec.dst, 6, tcp, spec.ttl);
        return buildEthernet(dstMac, srcMac, 0x0800, ip);
      }
      case 'ospf': {
        const body = buildOSPFHello(spec.ospfRouterId || spec.src,
          spec.area || '0.0.0.0', spec.mask, spec.helloInt, spec.deadInt, spec.prio);
        const ip = buildIPv4(spec.src, spec.dst || '224.0.0.5', 89, body, 1);
        const mcast = Uint8Array.from([0x01, 0x00, 0x5e, 0x00, 0x00, 0x05]);
        return buildEthernet(spec.dst ? dstMac : mcast, srcMac, 0x0800, ip);
      }
      default:
        throw new Error('unknown proto: ' + spec.proto);
    }
  }

  global.RouterPackets = { buildPacket, macFromId, buildIfaceMac };
})(window);

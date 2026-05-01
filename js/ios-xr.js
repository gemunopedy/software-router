// IOS-XR CLI エミュレーション。
// commands.js から os === 'ios-xr' のときに呼ばれる。
//
// 公開:
//   RouterIosXr.handleCommand(parts, state, io)
//   RouterIosXr.complete(line, router, state) → string[]
//   RouterIosXr.restoreBgpSessions(router)
(function (global) {
  const Storage = global.RouterStorage;
  const Packets = global.RouterPackets;

  // ---- ユーティリティ ----

  // 省略コマンド展開: tok が cands の唯一前方一致なら展開、曖昧/不明なら原文維持
  function _ex(tok, cands) {
    const t = (tok || '').toLowerCase();
    if (!t || cands.includes(t)) return t;
    const m = cands.filter(c => c.startsWith(t));
    return m.length === 1 ? m[0] : t;
  }

  function _prefixToMask(bits) {
    const n = parseInt(bits, 10);
    if (n <= 0) return '0.0.0.0';
    if (n >= 32) return '255.255.255.255';
    const mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - n));
    return [(mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF].join('.');
  }

  function _maskToPrefix(mask) {
    return (mask || '').split('.').reduce((n, o) => {
      let b = parseInt(o, 10) | 0, c = 0;
      while (b & 0x80) { c++; b = (b << 1) & 0xff; }
      return n + c;
    }, 0);
  }

  // CIDR (x.x.x.x/y) または dotted (x.x.x.x M.M.M.M) からマスクを返す
  function _normalizeMask(ipOrCidr, mask) {
    if (!mask && ipOrCidr && ipOrCidr.includes('/')) {
      return _prefixToMask(ipOrCidr.split('/')[1]);
    }
    return mask || '255.255.255.0';
  }

  function _normalizeIp(ipOrCidr) {
    return ipOrCidr ? ipOrCidr.split('/')[0] : ipOrCidr;
  }

  // ---- config パーサ ----

  function parseInterfaces(cfg) {
    const blocks = [];
    let cur = null;
    for (const raw of (cfg || '').split('\n')) {
      const t = raw.trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { cur = { name: im[1], lines: [] }; blocks.push(cur); continue; }
      if (cur) {
        if (/^[^ !]/.test(t) && t !== '') { cur = null; continue; }
        if (t.startsWith(' ') || t.startsWith('\t')) cur.lines.push(t.trim());
      }
    }
    return blocks;
  }

  function getIfIpInfo(blk) {
    for (const l of blk.lines) {
      // CIDR: ipv4 address 10.0.0.1/24
      const m1 = l.match(/^ipv4\s+address\s+([\d.]+)\/([\d]+)/i);
      if (m1) return { ip: m1[1], mask: _prefixToMask(parseInt(m1[2])) };
      // dotted: ipv4 address 10.0.0.1 255.255.255.0
      const m2 = l.match(/^ipv4\s+address\s+([\d.]+)\s+([\d.]+)/i);
      if (m2) return { ip: m2[1], mask: m2[2] };
    }
    return null;
  }

  function isIfShutdown(blk) {
    let down = false;
    for (const l of blk.lines) {
      if (/^shutdown$/i.test(l)) down = true;
      else if (/^no\s+shutdown$/i.test(l)) down = false;
    }
    return down;
  }

  function getVrfDefinitions(cfg) {
    const result = [];
    const lines = (cfg || '').split('\n');
    let cur = null;
    for (const raw of lines) {
      const t = raw.trimEnd();
      const m = t.match(/^vrf\s+(\S+)/i);
      if (m && !/^vrf-policy/i.test(t)) { cur = { name: m[1], rd: '', importRTs: [], exportRTs: [] }; result.push(cur); continue; }
      if (!cur) continue;
      if (/^[^ \t!]/.test(t) && t !== '') { cur = null; continue; }
      const line = t.trim();
      if (/^address-family\s+ipv4/i.test(line) || /^exit-address-family/i.test(line) || line === '!' || line === '') continue;
      if (/^rd\s+/i.test(line)) { cur.rd = line.replace(/^rd\s+/i, ''); continue; }
      const imp = line.match(/^import\s+route-target\s+(\S+)/i);
      if (imp) { cur.importRTs.push(imp[1]); continue; }
      const exp = line.match(/^export\s+route-target\s+(\S+)/i);
      if (exp) { cur.exportRTs.push(exp[1]); continue; }
    }
    return result;
  }

  function getIfVrf(iface) {
    for (const l of iface.lines) {
      const m = l.match(/^vrf\s+(\S+)/i);
      if (m) return m[1];
    }
    return null;
  }

  function getVrfStaticRoutes(cfg, vrfName) {
    const result = [];
    const lines = (cfg || '').split('\n');
    let inVrf = false;
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (new RegExp(`^vrf\\s+${vrfName}\\s*$`, 'i').test(t)) { inVrf = true; continue; }
      if (inVrf) {
        if (/^[^ \t!]/.test(t) && t !== '') { inVrf = false; continue; }
        const sm = t.trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)\s+(\S+)(?:\s+(\d+))?/);
        if (sm) {
          result.push({ prefix: sm[1], prefixLen: parseInt(sm[2]), nexthop: sm[3], ad: sm[4] ? parseInt(sm[4]) : 1 });
        }
      }
    }
    return result;
  }

  function getHostname(cfg) {
    const m = (cfg || '').match(/^hostname\s+(\S+)/im);
    return m ? m[1] : null;
  }

  function getSrConfig(cfg) {
    const lines = (cfg || '').split('\n');
    let inSrBlock = false, srgbBase = 16000, srgbEnd = 23999;
    let srEnabled = false;
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (/^segment-routing\s*$/i.test(t)) { inSrBlock = true; continue; }
      if (inSrBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inSrBlock = false; continue; }
        const gbM = t.trim().match(/^global-block\s+(\d+)\s+(\d+)/i);
        if (gbM) { srgbBase = parseInt(gbM[1]); srgbEnd = parseInt(gbM[2]); srEnabled = true; }
      }
    }

    // Check ISIS with SR in address-family
    let igpType = null;
    let inIsis = false, inIsisAf = false, inOspf = false, inOspfAf = false;
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (/^router\s+isis\s+/i.test(t)) { inIsis = true; inOspf = false; inIsisAf = false; inOspfAf = false; continue; }
      if (/^router\s+ospf\s+/i.test(t)) { inOspf = true; inIsis = false; inIsisAf = false; inOspfAf = false; continue; }
      if (/^[^ \t!]/.test(t) && t !== '') { inIsis = false; inOspf = false; inIsisAf = false; inOspfAf = false; continue; }
      if (inIsis) {
        if (/^\s+address-family\s+ipv4\s+unicast/i.test(t)) { inIsisAf = true; continue; }
        if (/^\s+exit-address-family/i.test(t)) { inIsisAf = false; continue; }
        if (inIsisAf && /^\s+segment-routing\s+mpls\s*$/i.test(t)) { igpType = 'isis'; srEnabled = true; }
      }
      if (inOspf) {
        if (/^\s+address-family\s+ipv4\s+unicast/i.test(t)) { inOspfAf = true; continue; }
        if (/^\s+exit-address-family/i.test(t)) { inOspfAf = false; continue; }
        if (inOspfAf && /^\s+segment-routing\s+mpls\s*$/i.test(t)) { igpType = 'ospf'; srEnabled = true; }
      }
    }

    if (!srEnabled) return null;

    // Collect prefix-sids from interface blocks (with or without address-family nesting)
    const prefixSids = {};
    const ifBlocks = parseInterfaces(cfg || '');
    for (const blk of ifBlocks) {
      if (!/^loopback/i.test(blk.name)) continue;
      const ipInfo = getIfIpInfo(blk);
      if (!ipInfo) continue;
      for (const l of blk.lines) {
        const m = l.match(/^prefix-sid\s+index\s+(\d+)/i);
        if (m) prefixSids[`${ipInfo.ip}/32`] = parseInt(m[1]);
      }
    }

    return { srEnabled, igpType, srgb: { base: srgbBase, end: srgbEnd }, prefixSids };
  }

  function getMplsConfig(cfg) {
    const ifaces = parseInterfaces(cfg);
    const mplsIfaces = ifaces
      .filter(blk => blk.lines.some(l => /^mpls\s*$/i.test(l) || /^mpls ip\s*$/i.test(l)))
      .map(blk => ({ name: blk.name, mplsEnabled: true, ldpEnabled: true }));
    if (!mplsIfaces.length) return null;
    return { interfaces: mplsIfaces, ldpRouterId: null };
  }

  // router static ブロック内の静的ルートを解析: [{prefix, prefixLen, nexthop, ad}]
  function getStaticRoutes(cfg) {
    const result = [];
    const lines = (cfg || '').split('\n');
    let inStatic = false;
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (/^router\s+static\s*$/i.test(t)) { inStatic = true; continue; }
      if (inStatic) {
        if (t !== '' && !/^[ \t]/.test(t)) { inStatic = false; continue; }
        if (/address-family/i.test(t.trim())) continue;
        const m = t.trim().match(/^([\d.]+)\/([\d]+)\s+([\d.]+)(?:\s+(\d+))?$/);
        if (m) result.push({ prefix: m[1], prefixLen: parseInt(m[2]), nexthop: m[3], ad: m[4] ? parseInt(m[4]) : 1 });
      }
    }
    return result;
  }

  // router static ブロックに行を追加/置換
  function _updateStaticLine(router, prefix, prefixLen, nexthop, ad) {
    const cfg = Storage.read(router.id, 'running') || '';
    const entry = ad !== 1 ? `${prefix}/${prefixLen} ${nexthop} ${ad}` : `${prefix}/${prefixLen} ${nexthop}`;
    const matchRe = new RegExp(`^${prefix.replace(/\./g,'\\.')}\\/${prefixLen}\\s+`);
    if (!/^router\s+static\s*$/im.test(cfg)) {
      Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter static\n  address-family ipv4 unicast\n   ${entry}\n`);
      return;
    }
    const lines = cfg.split('\n');
    let inStatic = false, inserted = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (/^router\s+static\s*$/i.test(t)) { inStatic = true; out.push(t); continue; }
      if (inStatic) {
        if (t !== '' && !/^[ \t]/.test(t)) {
          if (!inserted) { out.push(`   ${entry}`); inserted = true; }
          inStatic = false;
        } else if (matchRe.test(t.trim())) {
          out.push(`   ${entry}`); inserted = true; continue;
        }
      }
      out.push(t);
    }
    if (!inserted) out.push(`   ${entry}`);
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // router static ブロックから行を削除
  function _removeStaticLine(router, prefix, prefixLen) {
    const cfg = Storage.read(router.id, 'running') || '';
    const matchRe = new RegExp(`^${prefix.replace(/\./g,'\\.')}\\/${prefixLen}\\s+`);
    let inStatic = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (/^router\s+static\s*$/i.test(t)) { inStatic = true; return true; }
      if (inStatic) {
        if (t !== '' && !/^[ \t]/.test(t)) { inStatic = false; return true; }
        if (matchRe.test(t.trim())) return false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // router static / address-family ipv6 unicast への行追加/置換
  function _updateIpv6StaticLine(router, prefix, prefixLen, nexthop, ad) {
    const cfg = Storage.read(router.id, 'running') || '';
    const entry = ad !== 1 ? `${prefix}/${prefixLen} ${nexthop} ${ad}` : `${prefix}/${prefixLen} ${nexthop}`;
    const matchRe = new RegExp(`^${prefix.replace(/:/g,'\\:')}\\/${prefixLen}\\s+`);
    if (!/^router\s+static\s*$/im.test(cfg)) {
      Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter static\n  address-family ipv6 unicast\n   ${entry}\n`);
      return;
    }
    // Already have router static block — insert into ipv6 AF section or append
    const lines = cfg.split('\n');
    let inStatic = false, inIpv6Af = false, inserted = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (/^router\s+static\s*$/i.test(t)) { inStatic = true; out.push(t); continue; }
      if (inStatic) {
        if (t !== '' && !/^[ \t]/.test(t)) {
          if (!inserted) {
            out.push('  address-family ipv6 unicast');
            out.push(`   ${entry}`);
            inserted = true;
          }
          inStatic = false;
        } else if (/address-family\s+ipv6/i.test(t.trim())) {
          inIpv6Af = true; out.push(t); continue;
        } else if (/address-family/i.test(t.trim())) {
          inIpv6Af = false; out.push(t); continue;
        } else if (inIpv6Af && matchRe.test(t.trim())) {
          out.push(`   ${entry}`); inserted = true; continue;
        }
      }
      out.push(t);
    }
    if (!inserted) out.push(`   ${entry}`);
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeIpv6StaticLine(router, prefix, prefixLen) {
    const cfg = Storage.read(router.id, 'running') || '';
    const matchRe = new RegExp(`^${prefix.replace(/:/g,'\\:')}\\/${prefixLen}\\s+`);
    let inStatic = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (/^router\s+static\s*$/i.test(t)) { inStatic = true; return true; }
      if (inStatic) {
        if (t !== '' && !/^[ \t]/.test(t)) { inStatic = false; return true; }
        if (matchRe.test(t.trim())) return false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function topoIdx(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // ---- interface ブロック操作 ----

  function _updateIfaceLine(router, ifaceName, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n');
    const headerRe = new RegExp(`^interface\\s+${ifaceName.replace(/\//g, '\\/')}\\s*$`, 'i');
    let inBlock = false, replaced = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; out.push(t); continue; }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; }
        else if (t.startsWith(' ') || t.startsWith('\t')) {
          if (matchRe.test(t.trim())) { out.push(' ' + newLine); replaced = true; continue; }
        }
      }
      out.push(t);
    }
    if (!replaced) {
      const insertIdx = out.findIndex(l => headerRe.test(l.trimEnd()));
      if (insertIdx >= 0) {
        let end = insertIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t') || out[end] === '')) end++;
        out.splice(end, 0, ' ' + newLine);
      } else {
        out.push(`interface ${ifaceName}`, ' ' + newLine);
      }
    }
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeIfaceLine(router, ifaceName, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^interface\\s+${ifaceName.replace(/\//g, '\\/')}\\s*$`, 'i');
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) return !matchRe.test(t.trim());
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // ---- router ブロック操作 ----

  function _updateRouterLine(router, procKey, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n');
    const headerRe = new RegExp(`^router\\s+${procKey.replace(/\s+/g, '\\s+')}\\s*$`, 'i');
    let inBlock = false, replaced = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; out.push(t); continue; }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; }
        else if (t.startsWith(' ') || t.startsWith('\t')) {
          if (matchRe.test(t.trim())) { out.push(' ' + newLine); replaced = true; continue; }
        }
      }
      out.push(t);
    }
    if (!replaced) {
      const insertIdx = out.findIndex(l => headerRe.test(l.trimEnd()));
      if (insertIdx >= 0) {
        let end = insertIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t') || out[end] === '')) end++;
        out.splice(end, 0, ' ' + newLine);
      }
    }
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeRouterLine(router, procKey, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+${procKey.replace(/\s+/g, '\\s+')}\\s*$`, 'i');
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) return !matchRe.test(t.trim());
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeRouterBlock(router, procKey) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+${procKey.replace(/\s+/g, '\\s+')}\\s*$`, 'i');
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { skip = true; return false; }
      if (skip) {
        if (t.startsWith(' ') || t.startsWith('\t') || t === '') return false;
        skip = false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _updateVrfLine(router, vrfName, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^vrf\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    const lines = cfg.split('\n');
    let inBlock = false, replaced = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; out.push(t); continue; }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; }
        else if (t.startsWith(' ') || t.startsWith('\t')) {
          if (matchRe.test(t.trim())) { out.push(' ' + newLine); replaced = true; continue; }
        }
      }
      out.push(t);
    }
    if (!replaced) {
      const insertIdx = out.findIndex(l => headerRe.test(l.trimEnd()));
      if (insertIdx >= 0) {
        let end = insertIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t')) &&
               !/^address-family/i.test(out[end].trim())) end++;
        out.splice(end, 0, ' ' + newLine);
      }
    }
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeVrfLine(router, vrfName, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^vrf\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) return !matchRe.test(t.trim());
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeVrfBlock(router, vrfName) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^vrf\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { skip = true; return false; }
      if (skip) {
        if (t.startsWith(' ') || t.startsWith('\t') || t === '') return false;
        skip = false;
      }
      return true;
    });
    const cfg2 = out.join('\n');
    const fwdRe = new RegExp(`^vrf\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let inIface = false;
    const out2 = cfg2.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (/^interface\s+/i.test(t)) { inIface = true; return true; }
      if (inIface && (t.startsWith(' ') || t.startsWith('\t'))) return !fwdRe.test(t.trim());
      if (inIface && /^[^ \t!]/.test(t) && t !== '') inIface = false;
      return true;
    });
    Storage.write(router.id, 'running', out2.join('\n'));
  }

  // ---- GARP ----

  function _sendGarp(router, ifaceName, addr) {
    if (!Packets) return;
    const cfg = Storage.read(router.id, 'running') || '';
    let ifaceIdx = 0, counter = 0;
    for (const line of cfg.split('\n')) {
      const m = line.match(/^interface\s+(\S+)/i);
      if (!m) continue;
      if (m[1].toLowerCase() === ifaceName.toLowerCase()) { ifaceIdx = counter; break; }
      counter++;
    }
    const mac = Packets.buildIfaceMac(topoIdx(router.id), ifaceIdx);
    const pkt = Packets.buildPacket({ proto: 'arp', op: 'reply', src: addr, dst: addr, srcMac: mac, targetMac: 'ff:ff:ff:ff:ff:ff' });
    const Pcap = global.RouterPcap;
    if (Pcap) { Pcap.append(router.id, pkt); if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus(); }
    if (global.RouterCapture) global.RouterCapture.emit(router.id, pkt, { iface: ifaceName });
  }

  // ---- OSPF ブロック操作 ----

  function _ifaceMatchLocal(a, b) {
    const norm = s => (s || '').toLowerCase()
      .replace(/^gigabitethernet/i, 'gi')
      .replace(/^loopback/i, 'lo')
      .replace(/\.0$/, '');
    const an = norm(a), bn = norm(b);
    return an === bn || an.startsWith(bn) || bn.startsWith(an);
  }

  function _parseOspfStruct(cfg, proc) {
    const headerRe = new RegExp(`^router\\s+ospf\\s+${proc.replace(/[-/]/g,'[-\\/]')}\\s*$`, 'i');
    const lines = (cfg || '').split('\n');
    const result = { routerId: null, areas: {} };
    let inBlock = false, curArea = null, curIface = null;

    for (const raw of lines) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; continue; }
      if (!inBlock) continue;
      if (t !== '' && !/^[ \t!]/.test(t)) break;
      const indent = t.length - t.trimStart().length;
      const trimmed = t.trim();
      if (!trimmed || trimmed === '!') { if (indent <= 1) curIface = null; continue; }

      if (indent <= 1) {
        curIface = null;
        const ridM = trimmed.match(/^router-id\s+([\d.]+)/i);
        if (ridM) { result.routerId = ridM[1]; curArea = null; continue; }
        const areaM = trimmed.match(/^area\s+(\S+)/i);
        if (areaM) { curArea = areaM[1]; if (!result.areas[curArea]) result.areas[curArea] = []; continue; }
        curArea = null;
      } else if (indent === 2 && curArea !== null) {
        const ifM = trimmed.match(/^interface\s+(\S+)/i);
        if (ifM) { curIface = { name: ifM[1], props: [] }; result.areas[curArea].push(curIface); continue; }
        curIface = null;
      } else if (indent >= 3 && curIface !== null) {
        curIface.props.push(trimmed);
      }
    }
    return result;
  }

  function _serializeOspfStruct(proc, parsed) {
    const lines = [`router ospf ${proc}`];
    if (parsed.routerId) lines.push(` router-id ${parsed.routerId}`);
    for (const [areaId, ifaces] of Object.entries(parsed.areas)) {
      lines.push(` area ${areaId}`);
      for (const iface of ifaces) {
        lines.push(`  interface ${iface.name}`);
        for (const prop of iface.props) lines.push(`   ${prop}`);
      }
    }
    return lines.join('\n');
  }

  function _writeOspfStruct(router, proc, parsed) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+ospf\\s+${proc.replace(/[-/]/g,'[-\\/]')}\\s*$`, 'i');
    let skip = false;
    const remaining = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { skip = true; return false; }
      if (skip) {
        if (t !== '' && !/^[ \t!]/.test(t)) { skip = false; return true; }
        return false;
      }
      return true;
    });
    Storage.write(router.id, 'running', remaining.join('\n').trimEnd() + '\n' + _serializeOspfStruct(proc, parsed) + '\n');
  }

  function _removeOspfBlock(router, proc) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+ospf\\s+${proc.replace(/[-/]/g,'[-\\/]')}\\s*$`, 'i');
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { skip = true; return false; }
      if (skip) {
        if (t !== '' && !/^[ \t!]/.test(t)) { skip = false; return true; }
        return false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _setOspfRouterId(router, proc, rid) {
    const cfg = Storage.read(router.id, 'running') || '';
    const parsed = _parseOspfStruct(cfg, proc);
    parsed.routerId = rid || null;
    _writeOspfStruct(router, proc, parsed);
  }

  function _ensureOspfArea(router, proc, areaId) {
    const cfg = Storage.read(router.id, 'running') || '';
    const parsed = _parseOspfStruct(cfg, proc);
    if (!parsed.areas[areaId]) { parsed.areas[areaId] = []; _writeOspfStruct(router, proc, parsed); }
  }

  function _removeOspfArea(router, proc, areaId) {
    const cfg = Storage.read(router.id, 'running') || '';
    const parsed = _parseOspfStruct(cfg, proc);
    delete parsed.areas[areaId];
    _writeOspfStruct(router, proc, parsed);
  }

  function _ensureOspfAreaIface(router, proc, areaId, ifaceName) {
    const cfg = Storage.read(router.id, 'running') || '';
    const parsed = _parseOspfStruct(cfg, proc);
    if (!parsed.areas[areaId]) parsed.areas[areaId] = [];
    if (!parsed.areas[areaId].find(i => _ifaceMatchLocal(i.name, ifaceName))) {
      parsed.areas[areaId].push({ name: ifaceName, props: [] });
      _writeOspfStruct(router, proc, parsed);
    }
  }

  function _removeOspfAreaIface(router, proc, areaId, ifaceName) {
    const cfg = Storage.read(router.id, 'running') || '';
    const parsed = _parseOspfStruct(cfg, proc);
    if (parsed.areas[areaId]) {
      parsed.areas[areaId] = parsed.areas[areaId].filter(i => !_ifaceMatchLocal(i.name, ifaceName));
      if (!parsed.areas[areaId].length) delete parsed.areas[areaId];
    }
    _writeOspfStruct(router, proc, parsed);
  }

  function _setOspfAreaIfProp(router, proc, areaId, ifaceName, propRe, propStr) {
    const cfg = Storage.read(router.id, 'running') || '';
    const parsed = _parseOspfStruct(cfg, proc);
    if (!parsed.areas[areaId]) parsed.areas[areaId] = [];
    let iface = parsed.areas[areaId].find(i => _ifaceMatchLocal(i.name, ifaceName));
    if (!iface) { iface = { name: ifaceName, props: [] }; parsed.areas[areaId].push(iface); }
    if (propRe) {
      const idx = iface.props.findIndex(p => propRe.test(p));
      if (idx >= 0) {
        if (propStr) iface.props[idx] = propStr;
        else iface.props.splice(idx, 1);
      } else if (propStr) {
        iface.props.push(propStr);
      }
    } else if (propStr) {
      iface.props.push(propStr);
    }
    _writeOspfStruct(router, proc, parsed);
  }

  // ---- IS-IS ブロック操作 (IOS-XR: インタフェースはブロック内の1行) ----

  function _updateIsisLine(router, procKey, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+isis\\s+${procKey.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    if (!headerRe.test(cfg)) {
      Storage.write(router.id, 'running', (cfg.trimEnd() + `\nrouter isis ${procKey}\n ${newLine}\n`));
      return;
    }
    const lines = cfg.split('\n');
    let inBlock = false, replaced = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; out.push(t); continue; }
      if (inBlock) {
        if (t !== '' && !/^[ \t]/.test(t)) {
          if (!replaced) { out.push(` ${newLine}`); replaced = true; }
          inBlock = false;
        } else if (matchRe.test(t.trim())) {
          out.push(` ${newLine}`); replaced = true; continue;
        }
      }
      out.push(t);
    }
    if (!replaced) out.push(` ${newLine}`);
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeIsisLine(router, procKey, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+isis\\s+${procKey.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; return true; }
      if (inBlock) {
        if (t !== '' && !/^[ \t]/.test(t)) { inBlock = false; return true; }
        if (matchRe.test(t.trim())) return false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeIsisBlock(router, procKey) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+isis\\s+${procKey.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { skip = true; return false; }
      if (skip) {
        if (t !== '' && !/^[ \t]/.test(t)) { skip = false; return true; }
        return false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _getIsisIfLine(cfg, procKey, ifaceName) {
    const headerRe = new RegExp(`^router\\s+isis\\s+${procKey.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    const ifRe = new RegExp(`^interface\\s+${ifaceName.replace(/[-/]/g, '[-\\/]')}\\b`, 'i');
    let inBlock = false;
    for (const raw of (cfg || '').split('\n')) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; continue; }
      if (!inBlock) continue;
      if (t !== '' && !/^[ \t]/.test(t)) break;
      if (ifRe.test(t.trim())) return t.trim();
    }
    return null;
  }

  function _setIsisIfProp(router, procKey, ifaceName, propRe, propStr) {
    const cfg = Storage.read(router.id, 'running') || '';
    const current = _getIsisIfLine(cfg, procKey, ifaceName) || `interface ${ifaceName}`;
    let newLine;
    if (propRe && propRe.test(current)) {
      newLine = current.replace(propRe, propStr).replace(/\s{2,}/, ' ').trim();
    } else if (propStr) {
      newLine = `${current} ${propStr}`.trim();
    } else {
      newLine = current;
    }
    const matchRe = new RegExp(`^interface\\s+${ifaceName.replace(/[-/]/g, '[-\\/]')}\\b`, 'i');
    _updateIsisLine(router, procKey, matchRe, newLine);
  }

  // ---- show コマンド ----

  const showHandlers = {};

  showHandlers['running-config'] = showHandlers['run'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'running') || '';
    const host = getHostname(cfg) || router.hostname || router.id;
    io.println('Building configuration...');
    io.println('');
    io.println(`!! IOS XR Configuration ${cfg ? cfg.length : 0} bytes`);
    io.println(`!! Last configuration change at ${new Date().toUTCString()} by cisco`);
    io.println('!');
    io.println(`hostname ${host}`);
    io.println('!');
    const ifaces = parseInterfaces(cfg);
    ifaces.sort((a, b) => /^loopback/i.test(a.name) ? -1 : /^loopback/i.test(b.name) ? 1 : 0);
    ifaces.forEach(blk => {
      io.println(`interface ${blk.name}`);
      blk.lines.forEach(l => { if (l.trim() !== '') io.println(' ' + l); });
      io.println('!');
    });
    // router blocks
    const lines = cfg.split('\n');
    let inRouter = false;
    const routerLines = [];
    for (const l of lines) {
      if (/^router\s+\S+/i.test(l)) { inRouter = true; routerLines.push(l); continue; }
      if (inRouter) {
        if (l !== '' && !/^[ \t!]/.test(l)) { inRouter = false; }
        else routerLines.push(l);
      }
    }
    if (routerLines.length) {
      routerLines.forEach(l => { if (l.trim() !== '') io.println(l); });
      io.println('!');
    }
    io.println('end');
    io.println('');
  };

  showHandlers['startup-config'] = showHandlers['start'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'startup') || '';
    io.println(`!! IOS XR Configuration`);
    io.println(cfg || '[empty]');
    io.println('end');
  };

  showHandlers['version'] = showHandlers['ver'] = (args, router, io) => {
    const host = getHostname(Storage.read(router.id, 'running') || '') || router.hostname || router.id;
    io.println('Cisco IOS XR Software, Version 7.11.2 (emulated)');
    io.println('Copyright (c) 2013-2024 by Cisco Systems, Inc.');
    io.println('');
    io.println(`${host} uptime is 0 minutes`);
    io.println('');
    io.println('cisco ASR9001 (P4040) processor with 4194304K bytes of memory.');
  };

  showHandlers['interfaces'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
    const sub = (args[0] || '').toLowerCase();
    const rIdx = topoIdx(router.id);
    const ifaces = parseInterfaces(cfg);
    if (sub === 'brief' || sub === '') {
      io.println('Interface                      IP-Address      Status                Protocol');
      ifaces.forEach((blk, idx) => {
        const ipInfo = getIfIpInfo(blk);
        const down = isIfShutdown(blk);
        const ip = ipInfo ? `${ipInfo.ip}/${_maskToPrefix(ipInfo.mask)}` : 'unassigned';
        const proto = down ? 'down' : 'up';
        io.println(`${blk.name.padEnd(31)}${ip.padEnd(16)}${proto.padEnd(22)}${proto}`);
      });
      return;
    }
    const target = args[0];
    const blk = ifaces.find(b => b.name.toLowerCase().startsWith((target || '').toLowerCase()));
    if (!blk) { io.println(`% Interface ${target} not found`); return; }
    const ipInfo = getIfIpInfo(blk);
    const down = isIfShutdown(blk);
    io.println(`${blk.name} is ${down ? 'administratively down' : 'up'}, line protocol is ${down ? 'down' : 'up'}`);
    if (ipInfo) io.println(`  Internet address is ${ipInfo.ip}/${_maskToPrefix(ipInfo.mask)}`);
    for (const l of blk.lines) {
      if (/^description/i.test(l)) io.println(`  ${l}`);
    }
  };

  showHandlers['ip'] = (args, router, io) => {
    const sub = _ex(args[0], ['interface','bgp','route']);
    if (sub === 'interface') {
      showHandlers['interfaces']([args[1] || 'brief'], router, io);
    } else if (sub === 'bgp') {
      showHandlers['bgp'](args.slice(1), router, io);
    } else if (sub === 'route') {
      showHandlers['route'](args.slice(1), router, io);
    } else {
      io.println(`% Unrecognized 'show ip ${sub}'`);
    }
  };

  showHandlers['bgp'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'running') || '';
    const bgpM = cfg.match(/^router\s+bgp\s+(\d+)/im);
    if (!bgpM) { io.println('% BGP not active'); return; }
    const asn = bgpM[1];
    const ridM = cfg.match(/^\s*bgp\s+router-id\s+([\d.]+)/im);
    const routerId = ridM ? ridM[1] : '0.0.0.0';
    const neighbors = [];
    const nRe = /^\s+neighbor\s+([\d.]+)\s+remote-as\s+(\d+)/gim;
    let nm;
    while ((nm = nRe.exec(cfg)) !== null) neighbors.push({ ip: nm[1], as: nm[2] });

    const sub = (args[0] || '').toLowerCase();
    if (sub === 'summary') {
      io.println(`BGP router identifier ${routerId}, local AS number ${asn}`);
      io.println('BGP generic scan interval 60 secs');
      io.println('BGP table state: Active');
      io.println('');
      io.println('Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd');
      neighbors.forEach(n => {
        const est  = RouterBgp.isEstablished(router.id, n.ip);
        const info = RouterBgp.getSessionInfo(router.id, n.ip);
        let updown = '00:00:00';
        let statePfx = 'Idle';
        if (est && info) {
          const sec = Math.floor((Date.now() - info.establishedAt) / 1000);
          const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
          updown = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
          const pfxCount = RouterBgp.getRib(router.id).filter(e => e.neighborIp === n.ip).length;
          statePfx = String(pfxCount);
        }
        io.println(`${n.ip.padEnd(16)}0 ${n.as.padStart(5)}       0       0        0    0    0 ${updown} ${statePfx}`);
      });
      io.println('');
      return;
    }

    io.println(`BGP router identifier ${routerId}, local AS number ${asn}`);
    io.println('Status codes: s suppressed, d damped, h history, * valid, > best');
    io.println('Origin codes: i - IGP, e - EGP, ? - incomplete');
    io.println('');
    io.println('   Network            Next Hop         Metric LocPrf Weight Path');
    const rib = RouterBgp.getRib(router.id);
    if (rib.length === 0) { io.println('% No BGP routes'); return; }
    rib.forEach(e => {
      const isSelf = e.neighborIp === 'self';
      const net = `${e.prefix}/${e.prefixLen}`.padEnd(19);
      const nh  = (isSelf ? '0.0.0.0' : e.nextHop).padEnd(17);
      const path = e.asPath.join(' ');
      io.println(`*>  ${net}${nh}           0             0 ${path} ${e.origin}`);
    });
  };

  showHandlers['route'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';

    if (args[0] && args[0].toLowerCase() === 'vrf' && args[1]) {
      const vrfName = args[1];
      const vrfCands = [];
      parseInterfaces(cfg).forEach(blk => {
        if (getIfVrf(blk) !== vrfName) return;
        if (isIfShutdown(blk)) return;
        const ipInfo = getIfIpInfo(blk);
        if (!ipInfo) return;
        const ipParts   = ipInfo.ip.split('.').map(Number);
        const maskParts = ipInfo.mask.split('.').map(Number);
        const net = ipParts.map((b, i) => b & maskParts[i]).join('.');
        const len = _maskToPrefix(ipInfo.mask);
        vrfCands.push({ type: 'C', prefix: net,       prefixLen: len, ad: 0, metric: 0, via: blk.name });
        vrfCands.push({ type: 'L', prefix: ipInfo.ip, prefixLen: 32,  ad: 0, metric: 0, via: blk.name });
      });
      getVrfStaticRoutes(cfg, vrfName).forEach(e => {
        vrfCands.push({ type: 'S', prefix: e.prefix, prefixLen: e.prefixLen, ad: e.ad, metric: 0, nexthop: e.nexthop });
      });
      io.println(`VRF: ${vrfName}`);
      io.println('Codes: C - connected, L - local, S - static, i - ISIS, O - OSPF, B - BGP');
      io.println('');
      if (vrfCands.length === 0) { io.println(`% No routes in VRF ${vrfName}`); return; }
      RouterRib.selectBest(vrfCands).forEach(r => {
        if (r.type === 'C') io.println(`C     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
        else if (r.type === 'L') io.println(`L     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
        else if (r.type === 'S') io.println(`S     ${r.prefix}/${r.prefixLen} [${r.ad}/0] via ${r.nexthop}`);
      });
      return;
    }

    io.println('Codes: C - connected, L - local, S - static, i - ISIS, O - OSPF, B - BGP');
    io.println('');

    const candidates = [];
    parseInterfaces(cfg).forEach(blk => {
      if (getIfVrf(blk)) return;
      if (isIfShutdown(blk)) return;
      const ipInfo = getIfIpInfo(blk);
      if (!ipInfo) return;
      const ipParts   = ipInfo.ip.split('.').map(Number);
      const maskParts = ipInfo.mask.split('.').map(Number);
      const net = ipParts.map((b, i) => b & maskParts[i]).join('.');
      const len = _maskToPrefix(ipInfo.mask);
      candidates.push({ type: 'C', prefix: net,       prefixLen: len, ad: 0, metric: 0, via: blk.name });
      candidates.push({ type: 'L', prefix: ipInfo.ip, prefixLen: 32,  ad: 0, metric: 0, via: blk.name });
    });
    getStaticRoutes(cfg).forEach(e => {
      candidates.push({ type: 'S', prefix: e.prefix, prefixLen: e.prefixLen, ad: e.ad, metric: 0, nexthop: e.nexthop });
    });
    RouterIsis.getRib(router.id).forEach(e => {
      candidates.push({ type: 'I', prefix: e.prefix, prefixLen: e.prefixLen, ad: 115, metric: e.metric, nexthop: e.nexthop, level: e.level });
    });
    RouterOspf.getRib(router.id).forEach(e => {
      candidates.push({ type: 'O', prefix: e.prefix, prefixLen: e.prefixLen, ad: RouterRib.AD.O, metric: e.metric, nexthop: e.nexthop });
    });
    RouterBgp.getRib(router.id).filter(e => e.selected && e.neighborIp !== 'self').forEach(e => {
      candidates.push({ type: 'B', prefix: e.prefix, prefixLen: e.prefixLen, ad: 20, metric: 0, nexthop: e.nextHop });
    });

    RouterRib.selectBest(candidates).forEach(r => {
      if (r.type === 'C') io.println(`C     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
      else if (r.type === 'L') io.println(`L     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
      else if (r.type === 'S') io.println(`S     ${r.prefix}/${r.prefixLen} [${r.ad}/0] via ${r.nexthop}`);
      else if (r.type === 'I') io.println(`i L${r.level}  ${r.prefix}/${r.prefixLen} [115/${r.metric}] via ${r.nexthop}`);
      else if (r.type === 'O') io.println(`O     ${r.prefix}/${r.prefixLen} [110/${r.metric}] via ${r.nexthop}`);
      else if (r.type === 'B') io.println(`B     ${r.prefix}/${r.prefixLen} [20/0] via ${r.nexthop}`);
    });
  };

  showHandlers['arp'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'running') || '';
    const rIdx = topoIdx(router.id);
    io.println('Address          Age        Hardware Addr   State      Type  Interface');
    parseInterfaces(cfg).forEach((blk, idx) => {
      if (/^loopback/i.test(blk.name)) return;
      if (isIfShutdown(blk)) return;
      const ipInfo = getIfIpInfo(blk);
      if (!ipInfo) return;
      const mac = Packets ? Packets.buildIfaceMac(rIdx, idx) : null;
      const macStr = mac ? Array.from(mac).map(b => b.toString(16).padStart(2,'0')).join(':') : '-';
      io.println(`${ipInfo.ip.padEnd(17)}-          ${macStr.padEnd(16)}Interface  ARPA  ${blk.name}`);
    });
    if (global.RouterSender && global.RouterSender.getArpEntries) {
      global.RouterSender.getArpEntries(router.id).forEach(e => {
        const macHex = Array.from(e.mac).map(b => b.toString(16).padStart(2,'0')).join(':');
        const age = Math.floor((Date.now() - e.ts) / 60000);
        io.println(`${e.ip.padEnd(17)}${String(age).padEnd(11)}${macHex.padEnd(16)}Dynamic    ARPA  ${e.iface || '-'}`);
      });
    }
  };

  showHandlers['vrf'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
    const vrfs = getVrfDefinitions(cfg);
    io.println('VRF                              RD                    Protocols             Interfaces');
    vrfs.forEach(vrf => {
      const ifaces = parseInterfaces(cfg)
        .filter(iface => getIfVrf(iface) === vrf.name)
        .map(iface => iface.name)
        .join(', ');
      io.println(vrf.name.padEnd(33) + (vrf.rd || 'not set').padEnd(22) + 'ipv4          ' + ifaces);
    });
    if (vrfs.length === 0) io.println('(no VRFs configured)');
  };

  showHandlers['ospf'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'running') || '';
    const procM = cfg.match(/^router\s+ospf\s+(\S+)/im);
    const proc = procM ? procM[1] : '1';
    const sub = _ex(args[0] || 'neighbor', ['neighbor','database']);

    if (sub === 'neighbor') {
      const neighbors = RouterOspf.getNeighbors(router.id);
      io.println('* Indicates MADJ interface');
      io.println(`Neighbors for OSPF ${proc}`);
      io.println('');
      io.println('Neighbor ID     Pri   State           Dead Time   Address         Interface');
      if (neighbors.length === 0) io.println(' (no OSPF neighbors)');
      neighbors.forEach(n => {
        io.println(`${n.routerId.padEnd(16)}1   FULL/DR         00:00:37    ${n.routerIp.padEnd(16)}${n.ifaceName}`);
      });
      io.println('');
      io.println(`Total neighbor count: ${neighbors.length}`);
    } else if (sub === 'database') {
      const db = RouterOspf.getDatabase(router.id);
      io.println(`OSPF Router with ID (${router.id}) (Process ID ${proc})`);
      io.println('');
      io.println('            Router Link States (Area 0.0.0.0)');
      io.println('');
      io.println('Link ID         ADV Router      Age  Seq#         Checksum Link count');
      db.forEach(e => {
        io.println(`${e.lsId.padEnd(16)}${e.routerId.padEnd(16)}${String(e.age).padEnd(5)}${e.seq.padEnd(13)}${e.checksum.padEnd(9)}${e.linkCount}`);
      });
    } else {
      io.println(`% Unknown 'show ospf ${args[0]}'`);
    }
  };

  showHandlers['isis'] = (args, router, io) => {
    const sub = _ex(args[0] || 'neighbors', ['neighbors','database','adjacency']);
    if (sub === 'neighbors' || sub === 'adjacency') {
      const cfg = Storage.read(router.id, 'running') || '';
      const procM = cfg.match(/^router\s+isis\s+(\S+)/im);
      const procName = procM ? procM[1] : 'default';
      const adjs = RouterIsis.getAdjacencies(router.id);
      io.println(`IS-IS ${procName} neighbors:`);
      io.println('System Id     Interface                SNPA          State Holdtime Type');
      if (adjs.length === 0) io.println(' (no IS-IS neighbors)');
      adjs.forEach(a => {
        io.println(`${a.sysId.padEnd(14)}${a.ifaceName.padEnd(25)}${'*PtoP*'.padEnd(14)}${a.state.padEnd(6)}${String(29).padEnd(9)}L${a.level}`);
      });
    } else if (sub === 'database') {
      const db = RouterIsis.getDatabase();
      io.println('IS-IS Level-2 Link State Database:');
      io.println('LSPID                 LSP Seq Num  LSP Checksum  LSP Holdtime  ATT/P/OL');
      db.forEach(e => {
        io.println(`${e.lspId.padEnd(22)}${e.seq.padEnd(13)}${e.checksum.padEnd(14)}${String(e.lifetime).padEnd(14)}0/0/0`);
      });
    }
  };

  showHandlers['mpls'] = (args, router, io) => {
    if (!window.RouterMpls) { io.println('% MPLS not initialized'); return; }
    const sub = _ex(args[0], ['ldp', 'forwarding']);
    if (sub === 'ldp') {
      const sub2 = _ex(args[1], ['neighbor', 'bindings']);
      if (sub2 === 'neighbor' || !args[1]) {
        const neighbors = window.RouterMpls.getNeighbors(router.id);
        if (neighbors.length === 0) { io.println('    (no LDP neighbors)'); return; }
        const cfg = Storage.read(router.id, 'running') || '';
        const ifList = parseInterfaces(cfg);
        let myLdp = null;
        const lo = ifList.find(b => /^loopback0$/i.test(b.name));
        if (lo) { const ipInfo = getIfIpInfo(lo); myLdp = ipInfo ? ipInfo.ip : null; }
        if (!myLdp) {
          const first = ifList.find(b => getIfIpInfo(b));
          if (first) { const ipInfo = getIfIpInfo(first); myLdp = ipInfo ? ipInfo.ip : router.id; }
          else myLdp = router.id;
        }
        neighbors.forEach(n => {
          const peerLdp = n.ldpId;
          io.println(`    Peer LDP Ident: ${peerLdp}; Local LDP Ident ${myLdp}:0`);
          io.println(`        TCP connection: ${peerLdp.replace(':0','')}.646 - ${myLdp}.59000`);
          io.println(`        State: Oper; Msgs sent/rcvd: 12/12`);
          io.println(`        Up time: ${n.uptime}`);
          io.println(`        LDP discovery sources:`);
          io.println(`          ${n.iface}, Src IP addr: ${n.neighborIp}`);
        });
        return;
      }
      if (sub2 === 'bindings') {
        const bindings = window.RouterMpls.getBindings(router.id);
        if (bindings.length === 0) { io.println('    (no LDP bindings)'); return; }
        bindings.forEach(b => {
          io.println(`  ${b.fec}, rev 2`);
          io.println(`        Local binding: label: ${b.localLabel}`);
          if (b.remoteBindings.length > 0) {
            io.println(`        Remote bindings: (${b.remoteBindings.length} peer)`);
            io.println(`            Peer        Label`);
            b.remoteBindings.forEach(r => {
              io.println(`            ${r.lsr.padEnd(12)}${r.label}`);
            });
          }
        });
        return;
      }
      io.println(`% Invalid input after 'show mpls ldp'`);
      return;
    }
    if (sub === 'forwarding') {
      const table = window.RouterMpls.getForwardingTable(router.id);
      io.println('Local  Outgoing    Prefix            Interface       Next Hop');
      io.println('Label  Label                         or ID');
      if (table.length === 0) { io.println('  (empty)'); return; }
      table.forEach(e => {
        const loc = String(e.inLabel).padEnd(7);
        const out = e.outLabel.padEnd(12);
        const pref = e.prefix.padEnd(18);
        const iface = (e.iface || '-').padEnd(16);
        io.println(`${loc}${out}${pref}${iface}${e.nexthop}`);
      });
      return;
    }
    io.println(`% Invalid input after 'show mpls'`);
  };

  showHandlers['segment-routing'] = (args, router, io) => {
    if (!window.RouterSr) { io.println('% Segment Routing not initialized'); return; }
    const sub = _ex(args[0] || 'mpls', ['mpls']);
    if (sub !== 'mpls') { io.println(`% Invalid input after 'show segment-routing'`); return; }
    const sub2 = _ex(args[1] || 'state', ['state','lb','forwarding']);
    if (sub2 === 'state') {
      const srState = window.RouterSr.getSrState(router.id);
      io.println(`  Segment Routing with MPLS: ${srState.srEnabled ? 'Enabled' : 'Disabled'}`);
      return;
    }
    if (sub2 === 'lb') {
      const blk = window.RouterSr.getSrLabelBlock(router.id);
      io.println(`  Label block: [ ${blk.base}, ${blk.end} ], Size: ${blk.size}, Allocated: ${blk.allocated}`);
      return;
    }
    if (sub2 === 'forwarding') {
      const entries = window.RouterSr.getSrLfib(router.id);
      io.println('Prefix              In Label  Out Label  Next Hop    Interface');
      if (entries.length === 0) { io.println('  (empty)'); return; }
      entries.forEach(e => {
        const outStr = e.action === 'pop' ? 'Pop' : String(e.outLabel);
        io.println(`${e.prefix.padEnd(20)}${String(e.inLabel).padEnd(10)}${outStr.padEnd(11)}${e.nexthop.padEnd(12)}${e.iface}`);
      });
      return;
    }
    io.println(`% Invalid input after 'show segment-routing mpls'`);
  };

  // show ipv6 interface / route / neighbors
  showHandlers['ipv6'] = (args, router, io) => {
    if (!window.RouterIpv6) { io.println('% IPv6 not initialized'); return; }
    const Ipv6 = window.RouterIpv6;
    const sub = _ex(args[0], ['interface','route','neighbors','neighbor']);
    if (sub === 'interface') {
      const brief = (args[1] || '').toLowerCase().startsWith('br');
      const ifaces = Ipv6.getInterfaceAddrs(router.id);
      if (brief) {
        for (const f of ifaces) {
          const ll = f.ipv6.find(a => a.type === 'link-local');
          io.println(f.name.padEnd(25) + '[up/up]  ' + (ll ? ll.addr.toUpperCase() : 'unassigned'));
        }
        return;
      }
      for (const f of ifaces) {
        const ll = f.ipv6.find(a => a.type === 'link-local');
        const globals = f.ipv6.filter(a => a.type !== 'link-local');
        io.println(`${f.name} is up, line protocol is up`);
        io.println('  IPv6 is enabled, link-local address is ' + (ll ? ll.addr.toUpperCase() : 'none'));
        globals.forEach(({ addr, prefixLen }) => {
          const netBig = Ipv6.networkIpv6(addr, prefixLen);
          io.println(`  Global unicast: ${addr.toUpperCase()}/${prefixLen}, subnet ${Ipv6.formatIpv6(netBig).toUpperCase()}/${prefixLen}`);
        });
      }
      return;
    }
    if (sub === 'route') {
      const staticOnly = (args[1] || '').toLowerCase().startsWith('st');
      const routes = Ipv6.getIpv6Routes(router.id);
      const filtered = staticOnly ? routes.filter(r => r.type === 'S') : routes;
      io.println(`IPv6 Routing Table (${filtered.length} entries)`);
      filtered.forEach(r => {
        if (r.type === 'C') io.println(`C   ${r.prefix.toUpperCase()}/${r.prefixLen} via ${r.iface}, directly connected`);
        else if (r.type === 'L') io.println(`L   ${r.prefix.toUpperCase()}/${r.prefixLen} via ${r.iface}, receive`);
        else if (r.type === 'S') io.println(`S   ${r.prefix.toUpperCase()}/${r.prefixLen} [${r.ad}/0] via ${r.nexthop.toUpperCase()}`);
      });
      if (filtered.length === 0) io.println('  (no IPv6 routes)');
      return;
    }
    if (sub === 'neighbors' || sub === 'neighbor') {
      const neighbors = Ipv6.getNdpNeighbors(router.id);
      io.println('IPv6 Address                            Age  Link-layer Addr  State  Interface');
      neighbors.forEach(n => {
        io.println(n.addr.toUpperCase().padEnd(40) + '0    ' + n.mac.padEnd(17) + n.state.padEnd(7) + n.iface);
      });
      if (neighbors.length === 0) io.println('  (no NDP neighbors)');
      return;
    }
    io.println(`% Invalid input after 'show ipv6'`);
  };

  // ---- メインコマンドハンドラ ----

  // モード別動詞候補
  const _ECANDS = ['configure','clear','commit','copy','disable','enable','exit','help','no','ping','send','show','write'];
  const _CCANDS = ['do','end','exit','hostname','interface','ip','no','router','vrf'];
  const _ICANDS = ['description','do','end','exit','ipv4','ipv6','mpls','no','shutdown','vrf'];
  const _BCANDS = ['bgp','do','end','exit','neighbor','network','no','router-id'];
  const _VDEFCANDS_XR = ['address-family', 'exit-address-family', 'rd', 'import', 'export', 'no', 'exit', 'end'];
  const _SCANDS = ['address-family','do','end','exit','no'];
  const _ISCANDS = ['address-family','end','exit','interface','is-type','net','no'];
  const _ISIFCANDS = ['address-family','end','exit','metric','no','passive','point-to-point'];
  const _OSPFCANDS = ['area','end','exit','no','router-id'];
  const _OSPFAREACANDS = ['end','exit','interface','no'];
  const _OSPFIFCANDS = ['cost','end','exit','network','no','passive'];

  function handleCommand(parts, state, io) {
    const router = state.router;
    const _vcands = state.configMode === 'if' ? _ICANDS
                  : state.configMode === 'router' ? _BCANDS
                  : state.configMode === 'static' ? _SCANDS
                  : state.configMode === 'isis' ? _ISCANDS
                  : state.configMode === 'isis-if' ? _ISIFCANDS
                  : state.configMode === 'ospf' ? _OSPFCANDS
                  : state.configMode === 'ospf-area' ? _OSPFAREACANDS
                  : state.configMode === 'ospf-if' ? _OSPFIFCANDS
                  : state.configMode === 'vrf' ? _VDEFCANDS_XR
                  : state.configMode ? _CCANDS
                  : _ECANDS;
    const verb = _ex(parts[0], _vcands);

    if (state.configMode) {
      if (verb === 'end') {
        state.configMode = null; state.configIface = null; state.configRouter = null;
        state.configIsisProcess = null; state.configIsisIface = null;
        state.configOspfProcess = null; state.configOspfArea = null; state.configOspfIface = null;
        state.configVrf = null;
        return true;
      }
      if (verb === 'exit') {
        if (state.configMode === 'isis-if') {
          state.configMode = 'isis'; state.configIsisIface = null;
        } else if (state.configMode === 'ospf-if') {
          state.configMode = 'ospf-area'; state.configOspfIface = null;
        } else if (state.configMode === 'ospf-area') {
          state.configMode = 'ospf'; state.configOspfArea = null;
        } else if (state.configMode === 'ospf') {
          state.configMode = 'global'; state.configOspfProcess = null;
        } else if (state.configMode === 'vrf') {
          state.configMode = 'global'; state.configVrf = null;
        } else if (state.configMode === 'static' && state.configStaticAf) {
          state.configStaticAf = null;
        } else if (state.configMode === 'if' || state.configMode === 'router' || state.configMode === 'static' || state.configMode === 'isis') {
          state.configMode = 'global'; state.configIface = null; state.configRouter = null;
          state.configIsisProcess = null; state.configIsisIface = null;
        } else {
          state.configMode = null;
        }
        return true;
      }

      // ---------- config-static モード ----------
      if (state.configMode === 'static') {
        // address-family ipv4/ipv6 unicast → set active AF
        if (verb === 'address-family') {
          const af = (parts[1] || '').toLowerCase();
          state.configStaticAf = af.startsWith('ipv6') ? 'ipv6' : 'ipv4';
          return true;
        }
        // exit from within an AF goes back to static root; exit from static goes to global
        // (exit is handled by the outer exit handler — override it here)
        // no <prefix/len> → delete
        if (verb === 'no') {
          const cidr = parts[1];
          if (!cidr || !cidr.includes('/')) { io.println('% Incomplete: <prefix/len> required'); return true; }
          const [prefix, lenStr] = cidr.split('/');
          if (state.configStaticAf === 'ipv6') {
            _removeIpv6StaticLine(router, prefix, parseInt(lenStr, 10));
          } else {
            _removeStaticLine(router, prefix, parseInt(lenStr, 10));
          }
          return true;
        }
        // <prefix/len> <nexthop> [<ad>]
        const cidr = parts[0], nexthop = parts[1];
        if (cidr && cidr.includes('/') && nexthop) {
          const [prefix, lenStr] = cidr.split('/');
          const ad = parts[2] && /^\d+$/.test(parts[2]) ? parseInt(parts[2]) : 1;
          if (state.configStaticAf === 'ipv6') {
            _updateIpv6StaticLine(router, prefix, parseInt(lenStr, 10), nexthop, ad);
          } else if (/^\d+\.\d+\.\d+\.\d+$/.test(nexthop)) {
            _updateStaticLine(router, prefix, parseInt(lenStr, 10), nexthop, ad);
          } else {
            io.println(`% Invalid nexthop: ${nexthop}`);
          }
          return true;
        }
        io.println(`% Invalid input in config-static: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-if ----------
      if (state.configMode === 'if') {
        const ifaceName = state.configIface;
        const p1 = _ex(parts[1], ['address','description','ipv4','shutdown']);

        // ipv4 address <ip>/<prefix> | <ip> <mask>
        if (verb === 'ipv4' && p1 === 'address') {
          const rawAddr = parts[2];
          if (!rawAddr) { io.println('% Incomplete command.'); return true; }
          const ip   = _normalizeIp(rawAddr);
          const mask = _normalizeMask(rawAddr, parts[3]);
          if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) { io.println('% Invalid address'); return true; }
          const len = _maskToPrefix(mask);
          _updateIfaceLine(router, ifaceName, /^ipv4\s+address\s+/i, `ipv4 address ${ip}/${len}`);
          _sendGarp(router, ifaceName, ip);
          return true;
        }

        // no ipv4 address
        if (verb === 'no' && p1 === 'ipv4') {
          _removeIfaceLine(router, ifaceName, /^ipv4\s+address\s+/i);
          return true;
        }

        // description
        if (verb === 'description') {
          _updateIfaceLine(router, ifaceName, /^description\s*/i, `description ${parts.slice(1).join(' ')}`);
          return true;
        }
        if (verb === 'no' && p1 === 'description') {
          _removeIfaceLine(router, ifaceName, /^description\s*/i);
          return true;
        }

        // shutdown / no shutdown
        if (verb === 'shutdown') {
          _updateIfaceLine(router, ifaceName, /^shutdown$/i, 'shutdown'); return true;
        }
        if (verb === 'no' && p1 === 'shutdown') {
          _removeIfaceLine(router, ifaceName, /^shutdown$/i); return true;
        }

        // vrf <name>
        if (verb === 'vrf') {
          const vrfName = parts[1];
          if (!vrfName) { io.println('% Incomplete command.'); return true; }
          _updateIfaceLine(router, ifaceName, /^vrf\s+/i, `vrf ${vrfName}`);
          return true;
        }
        // no vrf
        if (verb === 'no' && _ex(parts[1], ['vrf','ipv4','description','shutdown']) === 'vrf') {
          _removeIfaceLine(router, ifaceName, /^vrf\s+/i);
          return true;
        }

        // mpls (LDP enable on interface)
        if (verb === 'mpls') {
          _updateIfaceLine(router, ifaceName, /^mpls$/i, 'mpls');
          if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
          return true;
        }
        // no mpls
        if (verb === 'no' && _ex(parts[1], ['mpls','ipv4','description','shutdown','vrf']) === 'mpls') {
          _removeIfaceLine(router, ifaceName, /^mpls$/i);
          if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
          return true;
        }

        // address-family / exit-address-family (passthrough for SR config)
        if (verb === 'address-family' || verb === 'exit-address-family') { return true; }

        // prefix-sid index <N>  (loopback only, IOS-XR style)
        if (verb === 'prefix-sid' && _ex(parts[1], ['index']) === 'index') {
          const n = parts[2];
          if (!n || isNaN(+n)) { io.println('% Incomplete: index value required'); return true; }
          _updateIfaceLine(router, ifaceName, /^prefix-sid\s+/i, `prefix-sid index ${n}`);
          if (window.RouterSr) window.RouterSr.recalculate();
          return true;
        }
        // no prefix-sid
        if (verb === 'no' && _ex(parts[1], ['prefix-sid']) === 'prefix-sid') {
          _removeIfaceLine(router, ifaceName, /^prefix-sid\s+/i);
          if (window.RouterSr) window.RouterSr.recalculate();
          return true;
        }

        // ipv6 address <addr>/<prefixLen>
        if (verb === 'ipv6' && (parts[1] || '').toLowerCase() === 'address') {
          const raw = parts[2];
          if (!raw || !raw.includes('/')) { io.println('% Incomplete command.'); return true; }
          const [addr, lenStr] = raw.split('/');
          _updateIfaceLine(router, ifaceName, /^ipv6\s+address\s+/i, `ipv6 address ${addr}/${lenStr}`);
          return true;
        }
        // no ipv6 address
        if (verb === 'no' && _ex(parts[1], ['ipv4','ipv6','description','shutdown','vrf','mpls','prefix-sid']) === 'ipv6') {
          _removeIfaceLine(router, ifaceName, /^ipv6\s+address\s+/i);
          return true;
        }

        io.println(`% Invalid input in config-if: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-router ----------
      if (state.configMode === 'router') {
        const procKey = state.configRouter;

        // neighbor <ip> remote-as <as>
        if (verb === 'neighbor') {
          const nIp = parts[1], key2 = _ex(parts[2], ['remote-as','update-source','description','shutdown']), val = parts[3];
          if (!nIp) { io.println('% Incomplete command.'); return true; }
          if (key2 === 'remote-as') {
            if (!val) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+remote-as\\s+`,'i'), `neighbor ${nIp} remote-as ${val}`);
            RouterBgp.teardownSession(router.id, nIp);
            RouterBgp.triggerSession(router, procKey, nIp, io);
          } else if (key2 === 'update-source') {
            if (!val) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+update-source\\s+`,'i'), `neighbor ${nIp} update-source ${val}`);
          } else if (key2 === 'description') {
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+description\\s+`,'i'), `neighbor ${nIp} description ${parts.slice(3).join(' ')}`);
          } else if (key2 === 'shutdown') {
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+shutdown$`,'i'), `neighbor ${nIp} shutdown`);
          } else {
            io.println(`% Unrecognized neighbor sub-command: ${key2}`);
          }
          return true;
        }

        // no neighbor <ip>
        if (verb === 'no' && _ex(parts[1], ['neighbor','network','bgp']) === 'neighbor') {
          const nIp = parts[2];
          if (!nIp) { io.println('% Incomplete command.'); return true; }
          _removeRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+`,'i'));
          RouterBgp.teardownSession(router.id, nIp);
          return true;
        }

        // bgp router-id
        if ((verb === 'bgp' && (parts[1]||'').toLowerCase() === 'router-id') || verb === 'router-id') {
          const rid = verb === 'bgp' ? parts[2] : parts[1];
          if (!rid) { io.println('% Incomplete command.'); return true; }
          _updateRouterLine(router, procKey, /^bgp\s+router-id\s+/i, `bgp router-id ${rid}`);
          return true;
        }

        // network <prefix>/<len> | <prefix> <mask>
        if (verb === 'network') {
          const rawPrefix = parts[1];
          if (!rawPrefix) { io.println('% Incomplete command.'); return true; }
          const prefix = _normalizeIp(rawPrefix);
          const prefixLen = rawPrefix.includes('/')
            ? parseInt(rawPrefix.split('/')[1], 10)
            : _maskToPrefix(_normalizeMask(rawPrefix, parts[3]));
          const line = `network ${prefix}/${prefixLen}`;
          _updateRouterLine(router, procKey, new RegExp(`^network\\s+${prefix.replace(/\./g,'\\.')}[\\/\\s]`,'i'), line);
          RouterBgp.installRoutes(router.id, [{ prefix, prefixLen }], '0.0.0.0', [], 'self');
          RouterBgp.advertise(router, prefix, prefixLen, io);
          return true;
        }

        // no network <prefix>
        if (verb === 'no' && _ex(parts[1], ['neighbor','network','bgp']) === 'network') {
          const rawPrefix = parts[2];
          if (!rawPrefix) { io.println('% Incomplete command.'); return true; }
          const prefix = _normalizeIp(rawPrefix);
          const prefixLen = rawPrefix.includes('/')
            ? parseInt(rawPrefix.split('/')[1], 10)
            : _maskToPrefix(_normalizeMask(rawPrefix, parts[4]));
          _removeRouterLine(router, procKey, new RegExp(`^network\\s+${prefix.replace(/\./g,'\\.')}[\\/\\s]`,'i'));
          RouterBgp.withdraw(router, prefix, prefixLen);
          return true;
        }

        io.println(`% Invalid input in config-router: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-isis ----------
      if (state.configMode === 'isis') {
        const proc = state.configIsisProcess;
        if (verb === 'net') {
          const net = parts[1];
          if (!net) { io.println('% Incomplete'); return true; }
          _updateIsisLine(router, proc, /^net\s+/i, `net ${net}`);
          RouterIsis.recalculate(router.id);
          return true;
        }
        if (verb === 'is-type') {
          const type = parts[1];
          if (!type) { io.println('% Incomplete'); return true; }
          _updateIsisLine(router, proc, /^is-type\s+/i, `is-type ${type}`);
          RouterIsis.recalculate(router.id);
          return true;
        }
        if (verb === 'interface') {
          const name = parts[1];
          if (!name) { io.println('% Incomplete'); return true; }
          const cfg = Storage.read(router.id, 'running') || '';
          if (!_getIsisIfLine(cfg, proc, name)) {
            const matchRe = new RegExp(`^interface\\s+${name.replace(/[-/]/g, '[-\\/]')}\\b`, 'i');
            _updateIsisLine(router, proc, matchRe, `interface ${name}`);
          }
          state.configMode = 'isis-if';
          state.configIsisIface = name;
          return true;
        }
        if (verb === 'address-family') { return true; }
        // segment-routing mpls (in ISIS address-family context)
        if (verb === 'segment-routing' && _ex(parts[1], ['mpls']) === 'mpls') {
          _updateIsisLine(router, proc, /^segment-routing\s+mpls\s*$/i, 'segment-routing mpls');
          if (window.RouterSr) window.RouterSr.recalculate();
          return true;
        }
        if (verb === 'no') {
          const sub = _ex(parts[1], ['net','is-type','interface','segment-routing']);
          if (sub === 'net') { _removeIsisLine(router, proc, /^net\s+/i); RouterIsis.recalculate(router.id); return true; }
          if (sub === 'is-type') { _removeIsisLine(router, proc, /^is-type\s+/i); RouterIsis.recalculate(router.id); return true; }
          if (sub === 'segment-routing') { _removeIsisLine(router, proc, /^segment-routing\s+mpls\s*$/i); if (window.RouterSr) window.RouterSr.recalculate(); return true; }
          if (sub === 'interface') {
            const name = parts[2];
            if (!name) { io.println('% Incomplete'); return true; }
            _removeIsisLine(router, proc, new RegExp(`^interface\\s+${name.replace(/[-/]/g, '[-\\/]')}\\b`, 'i'));
            RouterIsis.recalculate(router.id);
            return true;
          }
        }
        io.println(`% Invalid input in config-isis: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-isis-if ----------
      if (state.configMode === 'isis-if') {
        const proc = state.configIsisProcess;
        const ifName = state.configIsisIface;
        if (verb === 'point-to-point' || verb === 'ptp') {
          _setIsisIfProp(router, proc, ifName, /\bptp\b/i, 'ptp');
          RouterIsis.recalculate(router.id);
          return true;
        }
        if (verb === 'passive') {
          _setIsisIfProp(router, proc, ifName, /\bpassive\b/i, 'passive');
          RouterIsis.recalculate(router.id);
          return true;
        }
        if (verb === 'metric') {
          const val = parts[1];
          if (!val || isNaN(+val)) { io.println('% Incomplete: metric value required'); return true; }
          _setIsisIfProp(router, proc, ifName, /\bmetric\s+\d+/i, `metric ${val}`);
          RouterIsis.recalculate(router.id);
          return true;
        }
        if (verb === 'address-family') { return true; }
        if (verb === 'no') {
          const sub = _ex(parts[1], ['passive','metric','point-to-point']);
          if (sub === 'passive') { _setIsisIfProp(router, proc, ifName, /\s*\bpassive\b/i, ''); RouterIsis.recalculate(router.id); return true; }
          if (sub === 'metric') { _setIsisIfProp(router, proc, ifName, /\s*\bmetric\s+\d+/i, ''); RouterIsis.recalculate(router.id); return true; }
          if (sub === 'point-to-point') { _setIsisIfProp(router, proc, ifName, /\s*\bptp\b/i, ''); RouterIsis.recalculate(router.id); return true; }
        }
        io.println(`% Invalid input in config-isis-if: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-ospf ----------
      if (state.configMode === 'ospf') {
        const proc = state.configOspfProcess;
        if (verb === 'router-id') {
          const rid = parts[1];
          if (!rid) { io.println('% Incomplete'); return true; }
          _setOspfRouterId(router, proc, rid);
          return true;
        }
        if (verb === 'area') {
          const areaId = parts[1];
          if (!areaId) { io.println('% Incomplete'); return true; }
          _ensureOspfArea(router, proc, areaId);
          state.configMode = 'ospf-area';
          state.configOspfArea = areaId;
          return true;
        }
        if (verb === 'no') {
          const sub2 = _ex(parts[1], ['router-id','area']);
          if (sub2 === 'router-id') { _setOspfRouterId(router, proc, null); return true; }
          if (sub2 === 'area') {
            const areaId = parts[2];
            if (!areaId) { io.println('% Incomplete'); return true; }
            _removeOspfArea(router, proc, areaId);
            RouterOspf.recalculate(router.id);
            return true;
          }
        }
        io.println(`% Invalid input in config-ospf: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-ospf-area ----------
      if (state.configMode === 'ospf-area') {
        const proc = state.configOspfProcess;
        const areaId = state.configOspfArea;
        if (verb === 'interface') {
          const name = parts[1];
          if (!name) { io.println('% Incomplete'); return true; }
          _ensureOspfAreaIface(router, proc, areaId, name);
          state.configMode = 'ospf-if';
          state.configOspfIface = name;
          return true;
        }
        if (verb === 'no') {
          const sub2 = _ex(parts[1], ['interface']);
          if (sub2 === 'interface') {
            const name = parts[2];
            if (!name) { io.println('% Incomplete'); return true; }
            _removeOspfAreaIface(router, proc, areaId, name);
            RouterOspf.recalculate(router.id);
            return true;
          }
        }
        io.println(`% Invalid input in config-ospf-area: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-ospf-if ----------
      if (state.configMode === 'ospf-if') {
        const proc = state.configOspfProcess;
        const areaId = state.configOspfArea;
        const ifName = state.configOspfIface;
        if (verb === 'cost') {
          const val = parts[1];
          if (!val || isNaN(+val)) { io.println('% Incomplete: cost value required'); return true; }
          _setOspfAreaIfProp(router, proc, areaId, ifName, /\bcost\s+\d+/i, `cost ${val}`);
          RouterOspf.recalculate(router.id);
          return true;
        }
        if (verb === 'passive') {
          _setOspfAreaIfProp(router, proc, areaId, ifName, /\bpassive\b/i, 'passive');
          RouterOspf.recalculate(router.id);
          return true;
        }
        if (verb === 'network') {
          _setOspfAreaIfProp(router, proc, areaId, ifName, /\bpoint-to-point\b/i, 'point-to-point');
          RouterOspf.recalculate(router.id);
          return true;
        }
        if (verb === 'no') {
          const sub2 = _ex(parts[1], ['cost','passive','network']);
          if (sub2 === 'cost') { _setOspfAreaIfProp(router, proc, areaId, ifName, /\bcost\s+\d+/i, null); RouterOspf.recalculate(router.id); return true; }
          if (sub2 === 'passive') { _setOspfAreaIfProp(router, proc, areaId, ifName, /\bpassive\b/i, null); RouterOspf.recalculate(router.id); return true; }
          if (sub2 === 'network') { _setOspfAreaIfProp(router, proc, areaId, ifName, /\bpoint-to-point\b/i, null); RouterOspf.recalculate(router.id); return true; }
        }
        io.println(`% Invalid input in config-ospf-if: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-vrf モード ----------
      if (state.configMode === 'vrf') {
        const vrfName = state.configVrf;
        if (verb === 'rd') {
          const val = parts[1];
          if (!val) { io.println('% Incomplete command.'); return true; }
          _updateVrfLine(router, vrfName, /^rd\s+/i, `rd ${val}`);
          return true;
        }
        if (verb === 'address-family' || verb === 'exit-address-family') { return true; }
        if (verb === 'import' && (parts[1] || '').toLowerCase() === 'route-target') {
          const rt = parts[2];
          if (!rt) { io.println('% Incomplete command.'); return true; }
          const newLine = `import route-target ${rt}`;
          const cfg2 = Storage.read(router.id, 'running') || '';
          const headerRe2 = new RegExp(`^vrf\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
          let inBlk = false, exists2 = false;
          for (const raw of cfg2.split('\n')) {
            const t = raw.trimEnd();
            if (headerRe2.test(t)) { inBlk = true; continue; }
            if (inBlk) {
              if (/^[^ \t!]/.test(t) && t !== '') break;
              if (t.trim().toLowerCase() === newLine.toLowerCase()) { exists2 = true; break; }
            }
          }
          if (!exists2) _updateVrfLine(router, vrfName, /^\x00/, newLine);
          return true;
        }
        if (verb === 'export' && (parts[1] || '').toLowerCase() === 'route-target') {
          const rt = parts[2];
          if (!rt) { io.println('% Incomplete command.'); return true; }
          const newLine = `export route-target ${rt}`;
          const cfg2 = Storage.read(router.id, 'running') || '';
          const headerRe2 = new RegExp(`^vrf\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
          let inBlk = false, exists2 = false;
          for (const raw of cfg2.split('\n')) {
            const t = raw.trimEnd();
            if (headerRe2.test(t)) { inBlk = true; continue; }
            if (inBlk) {
              if (/^[^ \t!]/.test(t) && t !== '') break;
              if (t.trim().toLowerCase() === newLine.toLowerCase()) { exists2 = true; break; }
            }
          }
          if (!exists2) _updateVrfLine(router, vrfName, /^\x00/, newLine);
          return true;
        }
        if (verb === 'no') {
          const sub2 = _ex(parts[1], ['rd', 'import', 'export']);
          if (sub2 === 'rd') { _removeVrfLine(router, vrfName, /^rd\s+/i); return true; }
          if (sub2 === 'import' && (parts[2] || '').toLowerCase() === 'route-target') {
            const rt = parts[3];
            if (!rt) { io.println('% Incomplete command.'); return true; }
            const matchRe2 = new RegExp(`^import\\s+route-target\\s+${rt.replace(/[.:]/g, '\\$&')}\\s*$`, 'i');
            _removeVrfLine(router, vrfName, matchRe2);
            return true;
          }
          if (sub2 === 'export' && (parts[2] || '').toLowerCase() === 'route-target') {
            const rt = parts[3];
            if (!rt) { io.println('% Incomplete command.'); return true; }
            const matchRe2 = new RegExp(`^export\\s+route-target\\s+${rt.replace(/[.:]/g, '\\$&')}\\s*$`, 'i');
            _removeVrfLine(router, vrfName, matchRe2);
            return true;
          }
        }
        io.println(`% Invalid input in config-vrf: ${parts.join(' ')}`);
        return true;
      }

      // ---------- global config ----------

      // interface <name>
      if (verb === 'interface' || verb === 'int') {
        const name = parts[1];
        if (!name) { io.println('% Incomplete command.'); return true; }
        const cfg = Storage.read(router.id, 'running') || '';
        if (!parseInterfaces(cfg).find(b => b.name.toLowerCase() === name.toLowerCase())) {
          Storage.write(router.id, 'running', (cfg.trimEnd() + `\ninterface ${name}\n`));
        }
        state.configMode = 'if';
        state.configIface = name;
        return true;
      }

      // router bgp <asn>
      if (verb === 'router' && _ex(parts[1], ['bgp','static','isis','ospf']) === 'bgp') {
        const asn = parts[2];
        if (!asn || isNaN(+asn)) { io.println('% Specify AS number.'); return true; }
        const procKey = `bgp ${asn}`;
        const cfg = Storage.read(router.id, 'running') || '';
        if (!new RegExp(`^router\\s+bgp\\s+${asn}\\s*$`, 'im').test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter bgp ${asn}\n`);
        }
        state.configMode = 'router';
        state.configRouter = procKey;
        return true;
      }

      // router static
      if (verb === 'router' && _ex(parts[1], ['bgp','static','isis','ospf']) === 'static') {
        const cfg = Storage.read(router.id, 'running') || '';
        if (!/^router\s+static\s*$/im.test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + '\nrouter static\n  address-family ipv4 unicast\n');
        }
        state.configMode = 'static';
        return true;
      }

      // router isis <PROCESS>
      if (verb === 'router' && _ex(parts[1], ['bgp','static','isis','ospf']) === 'isis') {
        const proc = parts[2] || 'default';
        const cfg = Storage.read(router.id, 'running') || '';
        if (!new RegExp(`^router\\s+isis\\s+${proc}\\s*$`, 'im').test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter isis ${proc}\n`);
        }
        state.configMode = 'isis';
        state.configIsisProcess = proc;
        return true;
      }

      // no router bgp <asn>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname']) === 'router' && _ex(parts[2], ['bgp','isis']) === 'bgp') {
        const asn = parts[3];
        if (!asn) { io.println('% Incomplete command.'); return true; }
        _removeRouterBlock(router, `bgp ${asn}`);
        return true;
      }

      // no router isis <PROCESS>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname']) === 'router' && _ex(parts[2], ['bgp','isis','ospf']) === 'isis') {
        const proc = parts[3];
        if (!proc) { io.println('% Incomplete command.'); return true; }
        _removeIsisBlock(router, proc);
        RouterIsis.recalculate(router.id);
        return true;
      }

      // router ospf <name>
      if (verb === 'router' && _ex(parts[1], ['bgp','static','isis','ospf']) === 'ospf') {
        const proc = parts[2] || '1';
        const cfg = Storage.read(router.id, 'running') || '';
        if (!new RegExp(`^router\\s+ospf\\s+${proc.replace(/[-/]/g,'[-\\/]')}\\s*$`, 'im').test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter ospf ${proc}\n`);
        }
        state.configMode = 'ospf';
        state.configOspfProcess = proc;
        return true;
      }

      // no router ospf <name>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname']) === 'router' && _ex(parts[2], ['bgp','isis','ospf']) === 'ospf') {
        const proc = parts[3];
        if (!proc) { io.println('% Incomplete command.'); return true; }
        _removeOspfBlock(router, proc);
        RouterOspf.recalculate(router.id);
        return true;
      }

      // hostname
      if (verb === 'hostname') {
        const name = parts[1];
        if (!name) { io.println('% Incomplete command.'); return true; }
        const cfg = Storage.read(router.id, 'running') || '';
        const updated = /^hostname\s+\S+/im.test(cfg)
          ? cfg.replace(/^hostname\s+\S+/im, `hostname ${name}`)
          : `hostname ${name}\n` + cfg;
        Storage.write(router.id, 'running', updated);
        return true;
      }

      // vrf <name>
      if (verb === 'vrf') {
        const vrfName = parts[1];
        if (!vrfName) { io.println('% Incomplete command.'); return true; }
        const cfg2 = Storage.read(router.id, 'running') || '';
        if (!new RegExp(`^vrf\\s+${vrfName}\\s*$`, 'im').test(cfg2)) {
          Storage.write(router.id, 'running', cfg2.trimEnd() + `\nvrf ${vrfName}\n address-family ipv4 unicast\n`);
        }
        state.configMode = 'vrf';
        state.configVrf = vrfName;
        return true;
      }
      // no vrf <name>
      if (verb === 'no' && _ex(parts[1], ['vrf']) === 'vrf') {
        const vrfName = parts[2];
        if (!vrfName) { io.println('% Incomplete command.'); return true; }
        _removeVrfBlock(router, vrfName);
        return true;
      }

      // segment-routing block (global-block <base> <end>)
      if (verb === 'segment-routing') {
        const base = parts[1], end = parts[2];
        const cfg2 = Storage.read(router.id, 'running') || '';
        if (base && end && !isNaN(+base) && !isNaN(+end)) {
          // segment-routing <base> <end>  shorthand
          const srLine = `segment-routing\n  global-block ${base} ${end}`;
          const updated = /^segment-routing\s*$/im.test(cfg2)
            ? cfg2.replace(/^segment-routing[\s\S]*?(?=\n[^ \t]|$)/m, srLine)
            : cfg2.trimEnd() + '\n' + srLine + '\n';
          Storage.write(router.id, 'running', updated);
        } else if (!base) {
          if (!/^segment-routing\s*$/im.test(cfg2)) {
            Storage.write(router.id, 'running', cfg2.trimEnd() + '\nsegment-routing\n');
          }
        }
        if (window.RouterSr) window.RouterSr.recalculate();
        return true;
      }
      // global-block <base> <end>  (inside segment-routing context — simplified flat handling)
      if (verb === 'global-block') {
        const base = parts[1], end = parts[2];
        if (!base || !end || isNaN(+base) || isNaN(+end)) { io.println('% Incomplete: global-block <base> <end>'); return true; }
        const cfg2 = Storage.read(router.id, 'running') || '';
        const gbLine = `  global-block ${base} ${end}`;
        let updated;
        if (/^segment-routing\s*$/im.test(cfg2)) {
          if (/^\s+global-block\s+/im.test(cfg2)) {
            updated = cfg2.replace(/^\s+global-block\s+.*$/im, gbLine);
          } else {
            updated = cfg2.replace(/^(segment-routing\s*$)/im, `$1\n${gbLine}`);
          }
        } else {
          updated = cfg2.trimEnd() + `\nsegment-routing\n${gbLine}\n`;
        }
        Storage.write(router.id, 'running', updated);
        if (window.RouterSr) window.RouterSr.recalculate();
        return true;
      }
      // no segment-routing
      if (verb === 'no' && _ex(parts[1], ['segment-routing']) === 'segment-routing') {
        const cfg2 = Storage.read(router.id, 'running') || '';
        Storage.write(router.id, 'running',
          cfg2.replace(/^segment-routing\s*\n(?:[ \t]+.*\n)*/im, ''));
        if (window.RouterSr) window.RouterSr.recalculate();
        return true;
      }

      io.println(`% Invalid input in config mode: ${parts.join(' ')}`);
      return true;
    }

    // ============================================================
    // Exec mode
    // ============================================================

    if (verb === 'configure' || verb === 'conf') {
      const sub = _ex(parts[1] || 'terminal', ['terminal']);
      if (sub === 'terminal' || sub === 'term' || sub === 't') {
        io.println('Enter configuration commands, one per line.  End with CNTL/Z or "end".');
        state.configMode = 'global'; state.configIface = null;
        return true;
      }
      io.println(`% Invalid input after 'configure ${sub}'`);
      return true;
    }

    // commit (XR style)
    if (verb === 'commit') {
      Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
      io.println('');
      io.println('% Configuration committed');
      return true;
    }

    if (verb === 'show' || verb === 'sh') {
      const _SHOW_KEYS = ['running-config','run','startup-config','start','version','ver','interfaces','ip','ipv6','bgp','route','arp','isis','ospf','vrf','mpls','segment-routing'];
      const sub = _ex(parts[1], _SHOW_KEYS);
      if (!sub) { io.println('% Incomplete command.'); return true; }
      const handler = showHandlers[sub];
      if (handler) { handler(parts.slice(2), router, io); return true; }
      io.println(`% Invalid input after 'show ${sub}'`);
      return true;
    }

    if (verb === 'write' || verb === 'wr') {
      io.println("% 'write memory' is not supported on IOS-XR. Use 'commit'.");
      return true;
    }

    if (verb === 'copy') {
      io.println("% 'copy' is not supported on IOS-XR. Use 'commit'.");
      return true;
    }

    // --- ping ipv6 ---
    if (verb === 'ping' && (parts[1] || '').toLowerCase() === 'ipv6') {
      const addr = parts[2];
      if (!addr) { io.println('% Usage: ping ipv6 <addr>'); return true; }
      if (!window.RouterIpv6) { io.println('% IPv6 not initialized'); return true; }
      const neighbors = window.RouterIpv6.getNdpNeighbors(router.id);
      const target = window.RouterIpv6.canonIpv6(addr);
      const reachable = neighbors.some(n => n.addr === target);
      io.println('Type escape sequence to abort.');
      io.println(`Sending 5, 100-byte ICMP Echos to ${addr}`);
      io.println(reachable ? '!!!!!' : '.....');
      io.println('');
      io.println(`Success rate is ${reachable ? 100 : 0} percent (${reachable ? '5/5' : '0/5'})`);
      return true;
    }

    return false;
  }

  // ---- Tab 補完 ----

  function complete(line, router, state) {
    const tokens = line.trimStart().split(/\s+/);
    const last = tokens[tokens.length - 1];
    const before = tokens.slice(0, -1).map(t => t.toLowerCase());

    function ifaceNames() {
      const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
      return (cfg.match(/^interface\s+(\S+)/gim) || []).map(l => l.replace(/^interface\s+/i,'').trim());
    }

    const mode = state && state.configMode;

    if (mode === 'if') {
      if (before.length === 0) return ['ipv4','description','mpls','shutdown','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if (v === 'ipv4' && before.length === 1) return ['address'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1) return ['ipv4','description','shutdown'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'global') {
      if (before.length === 0) return ['interface','hostname','router','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if ((v === 'interface'||v==='int') && before.length === 1) return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'router' && before.length === 1) return ['bgp', 'isis', 'ospf'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1) return ['interface','router'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before[1] === 'router' && before.length === 2) return ['bgp', 'isis', 'ospf'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'router') {
      if (before.length === 0) return ['neighbor','network','bgp','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if (v === 'bgp' && before.length === 1) return ['router-id'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'neighbor' && before.length === 2) return ['remote-as','update-source','description','shutdown'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1) return ['neighbor','network'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'ospf') {
      if (before.length === 0) return ['area','router-id','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if (v === 'no' && before.length === 1) return ['area','router-id'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'ospf-area') {
      if (before.length === 0) return ['interface','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if (v === 'interface' && before.length === 1) return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1) return ['interface'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'ospf-if') {
      if (before.length === 0) return ['cost','passive','network','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if (v === 'network' && before.length === 1) return ['point-to-point'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1) return ['cost','passive','network'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    // exec mode
    if (before.length === 0) {
      return ['configure','show','commit','load-config','clear','exit','help']
        .filter(c => c.startsWith(last.toLowerCase()));
    }
    const verb = before[0];
    if (verb === 'configure' || verb === 'conf') {
      if (before.length === 1) return ['terminal'].filter(s => s.startsWith(last.toLowerCase()));
    }
    if (verb === 'show' || verb === 'sh') {
      if (before.length === 1) {
        return ['bgp','mpls','route','interfaces','running-config','startup-config','version','arp','isis','ospf']
          .filter(s => s.startsWith(last.toLowerCase()));
      }
      const sub = before[1];
      if (sub === 'bgp' && before.length === 2) return ['summary'].filter(s => s.startsWith(last.toLowerCase()));
      if (sub === 'interfaces' && before.length === 2) return ['brief',...ifaceNames()].filter(s => s.toLowerCase().startsWith(last.toLowerCase()));
      if (sub === 'ospf' && before.length === 2) return ['neighbor','database'].filter(s => s.startsWith(last.toLowerCase()));
    }
    if (verb === 'write' || verb === 'wr') {
      if (before.length === 1) return ['memory'].filter(s => s.startsWith(last.toLowerCase()));
    }
    return [];
  }

  // ---- BGP セッション復元 ----

  function restoreBgpSessions(router) {
    RouterBgp.restoreSessions(router);
  }

  // ---- IOS-XR config パーサ（RouterBgp 登録用）----

  const _iosXrParser = {
    getBgpAs(cfg) {
      const m = (cfg || '').match(/^router\s+bgp\s+(\d+)/im);
      return m ? parseInt(m[1], 10) : 65000;
    },
    getBgpRouterId(cfg) {
      const ridM = (cfg || '').match(/^\s*bgp\s+router-id\s+([\d.]+)/im);
      if (ridM) return ridM[1];
      const ifaces = parseInterfaces(cfg);
      const lo = ifaces.find(b => /^loopback0$/i.test(b.name));
      if (lo) { const info = getIfIpInfo(lo); if (info) return info.ip; }
      for (const b of ifaces) { const info = getIfIpInfo(b); if (info) return info.ip; }
      return '0.0.0.0';
    },
    getBgpNetworks(cfg) {
      const lines = (cfg || '').split('\n');
      const hi = lines.findIndex(l => /^router\s+bgp\s+\d+\s*$/i.test(l.trimEnd()));
      if (hi < 0) return [];
      const result = [];
      for (let i = hi + 1; i < lines.length; i++) {
        const l = lines[i];
        if (l !== '' && !/^[ \t]/.test(l)) break;
        // network 10.0.0.0/24 or network 10.0.0.0 255.255.255.0
        const m1 = l.trim().match(/^network\s+([\d.]+)\/([\d]+)$/i);
        if (m1) { result.push({ prefix: m1[1], prefixLen: parseInt(m1[2], 10) }); continue; }
        const m2 = l.trim().match(/^network\s+([\d.]+)\s+([\d.]+)$/i);
        if (m2) { result.push({ prefix: m2[1], prefixLen: _maskToPrefix(m2[2]) }); }
      }
      return result;
    },
    hasBgpNeighbor(cfg, peerIp) {
      return /^router bgp\b/im.test(cfg || '') &&
        new RegExp(`^\\s*neighbor\\s+${peerIp.replace(/\./g,'\\.')}\\s+remote-as`, 'im').test(cfg || '');
    },
    getNeighborUpdateSource(cfg, neighborIp) {
      const m = (cfg || '').match(new RegExp(`neighbor\\s+${neighborIp}\\s+update-source\\s+(\\S+)`, 'i'));
      return m ? m[1] : null;
    },
    getInterfaceList(cfg) {
      return parseInterfaces(cfg || '').map(blk => {
        const info = getIfIpInfo(blk);
        return info ? { name: blk.name, ip: info.ip, mask: info.mask } : null;
      }).filter(Boolean);
    },
    getNeighbors(cfg) {
      const bgpM = (cfg || '').match(/^router\s+bgp\s+(\S+)/im);
      if (!bgpM) return [];
      const procKey = `bgp ${bgpM[1]}`;
      const result = [];
      const nRe = /^\s+neighbor\s+([\d.]+)\s+remote-as\s+\d+/gim;
      let nm;
      while ((nm = nRe.exec(cfg)) !== null) result.push({ neighborIp: nm[1], procKey });
      return result;
    },
  };

  RouterBgp.registerOsParser('ios-xr', _iosXrParser);

  // IS-IS パーサ登録
  RouterIsis.registerOsParser('ios-xr', {
    getIsisConfig(cfg) {
      const m = (cfg || '').match(/^router\s+isis\s+(\S+)/im);
      if (!m) return null;
      const procKey = m[1];
      const lines = (cfg || '').split('\n');
      const headerRe = new RegExp(`^router\\s+isis\\s+${procKey.replace(/[-/]/g,'[-\\/]')}\\s*$`, 'i');
      let inBlock = false, net = null, isType = 'level-1-2';
      const interfaces = [];
      for (const raw of lines) {
        const t = raw.trimEnd();
        if (headerRe.test(t)) { inBlock = true; continue; }
        if (!inBlock) continue;
        if (t !== '' && !/^[ \t]/.test(t)) break;
        const trimmed = t.trim();
        const nm = trimmed.match(/^net\s+(\S+)/i);
        if (nm) { net = nm[1]; continue; }
        const tm = trimmed.match(/^is-type\s+(\S+)/i);
        if (tm) { isType = tm[1]; continue; }
        const ifM = trimmed.match(/^interface\s+(\S+)(.*)?/i);
        if (ifM) {
          const name = ifM[1];
          const rest = (ifM[2] || '').trim().toLowerCase();
          const passive = /\bpassive\b/.test(rest);
          const metM = rest.match(/metric\s+(\d+)/);
          const metric = metM ? parseInt(metM[1]) : 10;
          interfaces.push({ name, metric, passive });
        }
      }
      if (!net) return null;
      return { process: procKey, net, isType, interfaces };
    },
    getInterfaceList(cfg) {
      return parseInterfaces(cfg || '').map(blk => {
        const info = getIfIpInfo(blk);
        return info ? { name: blk.name, ip: info.ip, mask: info.mask } : null;
      }).filter(Boolean);
    },
  });

  // OSPF パーサ登録
  RouterOspf.registerOsParser('ios-xr', {
    getOspfConfig(cfg) {
      const m = (cfg || '').match(/^router\s+ospf\s+(\S+)/im);
      if (!m) return null;
      const proc = m[1];
      const struct = _parseOspfStruct(cfg || '', proc);
      const routerId = struct.routerId || null;
      const areas = {};
      for (const [areaId, ifaceArr] of Object.entries(struct.areas)) {
        const ifaces = ifaceArr.map(ifObj => {
          const propsStr = (ifObj.props || []).join(' ');
          const passM = /\bpassive\b/.test(propsStr);
          const costM = propsStr.match(/\bcost\s+(\d+)/i);
          return { name: ifObj.name, cost: costM ? parseInt(costM[1]) : 1, passive: passM };
        });
        areas[areaId] = { interfaces: ifaces };
      }
      return { process: proc, routerId, areas };
    },
    getInterfaceList(cfg) {
      return parseInterfaces(cfg || '').map(blk => {
        const info = getIfIpInfo(blk);
        return info ? { name: blk.name, ip: info.ip, mask: info.mask } : null;
      }).filter(Boolean);
    },
  });

  // MPLS パーサ登録
  if (window.RouterMpls) {
    window.RouterMpls.registerOsParser('ios-xr', {
      getMplsConfig,
      getInterfaceList(cfg) {
        return parseInterfaces(cfg || '').map(blk => {
          const info = getIfIpInfo(blk);
          return info ? { name: blk.name, ip: info.ip, mask: info.mask } : null;
        }).filter(Boolean);
      },
    });
  }

  // SR パーサ登録
  if (window.RouterSr) {
    window.RouterSr.registerOsParser('ios-xr', {
      getSrConfig,
      getInterfaceList(cfg) {
        return parseInterfaces(cfg || '').map(blk => {
          const info = getIfIpInfo(blk);
          return info ? { name: blk.name, ip: info.ip, mask: info.mask } : null;
        }).filter(Boolean);
      },
    });
  }

  global.RouterIosXr = { handleCommand, complete, restoreBgpSessions };

  // IPv6 パーサ登録
  if (window.RouterIpv6) {
    window.RouterIpv6.registerOsParser('ios-xr', {
      getInterfaceAddrs(cfg) {
        return parseInterfaces(cfg).map(blk => {
          const ipv4Info = getIfIpInfo(blk);
          const ipv4 = ipv4Info ? [{ ip: ipv4Info.ip, prefixLen: _maskToPrefix(ipv4Info.mask) }] : [];
          const ipv6 = [];
          for (const l of blk.lines) {
            const m6 = l.match(/^ipv6\s+address\s+([\w:]+)\/([\d]+)/i);
            if (m6) ipv6.push({ addr: m6[1], prefixLen: parseInt(m6[2], 10), type: 'global' });
          }
          return { name: blk.name, ipv4, ipv6, shutdown: false };
        });
      },
      getIpv6StaticRoutes(cfg) {
        const result = [];
        const lines = (cfg || '').split('\n');
        let inStatic = false, inIpv6Af = false;
        for (const raw of lines) {
          const t = raw.trimEnd();
          if (/^router\s+static\s*$/i.test(t)) { inStatic = true; continue; }
          if (inStatic) {
            if (t !== '' && !/^[ \t]/.test(t)) { inStatic = false; inIpv6Af = false; continue; }
            if (/address-family\s+ipv6/i.test(t.trim())) { inIpv6Af = true; continue; }
            if (/address-family/i.test(t.trim())) { inIpv6Af = false; continue; }
            if (inIpv6Af) {
              const m = t.trim().match(/^([\w:]+)\/([\d]+)\s+([\w:]+)(?:\s+(\d+))?$/);
              if (m) result.push({ prefix: m[1], prefixLen: parseInt(m[2], 10), nexthop: m[3], ad: m[4] ? parseInt(m[4], 10) : 1 });
            }
          }
        }
        return result;
      },
    });
  }
})(window);

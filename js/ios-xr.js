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

  function getHostname(cfg) {
    const m = (cfg || '').match(/^hostname\s+(\S+)/im);
    return m ? m[1] : null;
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
    const sub = (args[0] || '').toLowerCase();
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
    io.println('Codes: C - connected, L - local, B - BGP');
    io.println('');
    const ifaces = parseInterfaces(cfg);
    ifaces.forEach(blk => {
      if (isIfShutdown(blk)) return;
      const ipInfo = getIfIpInfo(blk);
      if (!ipInfo) return;
      const ipParts = ipInfo.ip.split('.').map(Number);
      const maskParts = ipInfo.mask.split('.').map(Number);
      const net = ipParts.map((b, i) => b & maskParts[i]).join('.');
      const len = _maskToPrefix(ipInfo.mask);
      io.println(`C     ${net}/${len} is directly connected, ${blk.name}`);
      io.println(`L     ${ipInfo.ip}/32 is directly connected, ${blk.name}`);
    });
    const bgpRoutes = RouterBgp.getRib(router.id).filter(e => e.selected && e.neighborIp !== 'self');
    bgpRoutes.forEach(e => {
      io.println(`B     ${e.prefix}/${e.prefixLen} [20/0] via ${e.nextHop}`);
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

  // ---- メインコマンドハンドラ ----

  function handleCommand(parts, state, io) {
    const router = state.router;
    const verb = (parts[0] || '').toLowerCase();

    if (state.configMode) {
      if (verb === 'end') {
        state.configMode = null; state.configIface = null; state.configRouter = null;
        return true;
      }
      if (verb === 'exit') {
        if (state.configMode === 'if' || state.configMode === 'router') {
          state.configMode = 'global'; state.configIface = null; state.configRouter = null;
        } else {
          state.configMode = null;
        }
        return true;
      }

      // ---------- config-if ----------
      if (state.configMode === 'if') {
        const ifaceName = state.configIface;

        // ipv4 address <ip>/<prefix> | <ip> <mask>
        if (verb === 'ipv4' && (parts[1] || '').toLowerCase() === 'address') {
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
        if (verb === 'no' && (parts[1]||'').toLowerCase() === 'ipv4') {
          _removeIfaceLine(router, ifaceName, /^ipv4\s+address\s+/i);
          return true;
        }

        // description
        if (verb === 'description') {
          _updateIfaceLine(router, ifaceName, /^description\s*/i, `description ${parts.slice(1).join(' ')}`);
          return true;
        }
        if (verb === 'no' && (parts[1]||'').toLowerCase() === 'description') {
          _removeIfaceLine(router, ifaceName, /^description\s*/i);
          return true;
        }

        // shutdown / no shutdown
        if (verb === 'shutdown') {
          _updateIfaceLine(router, ifaceName, /^shutdown$/i, 'shutdown'); return true;
        }
        if (verb === 'no' && (parts[1]||'').toLowerCase() === 'shutdown') {
          _removeIfaceLine(router, ifaceName, /^shutdown$/i); return true;
        }

        io.println(`% Invalid input in config-if: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-router ----------
      if (state.configMode === 'router') {
        const procKey = state.configRouter;

        // neighbor <ip> remote-as <as>
        if (verb === 'neighbor') {
          const nIp = parts[1], key2 = (parts[2]||'').toLowerCase(), val = parts[3];
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
        if (verb === 'no' && (parts[1]||'').toLowerCase() === 'neighbor') {
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
        if (verb === 'no' && (parts[1]||'').toLowerCase() === 'network') {
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
      if (verb === 'router' && (parts[1]||'').toLowerCase() === 'bgp') {
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

      // no router bgp <asn>
      if (verb === 'no' && (parts[1]||'').toLowerCase() === 'router' && (parts[2]||'').toLowerCase() === 'bgp') {
        const asn = parts[3];
        if (!asn) { io.println('% Incomplete command.'); return true; }
        _removeRouterBlock(router, `bgp ${asn}`);
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

      io.println(`% Invalid input in config mode: ${parts.join(' ')}`);
      return true;
    }

    // ============================================================
    // Exec mode
    // ============================================================

    if (verb === 'configure' || verb === 'conf') {
      const sub = (parts[1] || 'terminal').toLowerCase();
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
      const sub = (parts[1] || '').toLowerCase();
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
      if (before.length === 0) return ['ipv4','description','shutdown','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if (v === 'ipv4' && before.length === 1) return ['address'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1) return ['ipv4','description','shutdown'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'global') {
      if (before.length === 0) return ['interface','hostname','router','no','exit','end'].filter(c => c.startsWith(last.toLowerCase()));
      const v = before[0];
      if ((v === 'interface'||v==='int') && before.length === 1) return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'router' && before.length === 1) return ['bgp'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1) return ['interface','router'].filter(s => s.startsWith(last.toLowerCase()));
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
        return ['bgp','route','interfaces','running-config','startup-config','version','arp']
          .filter(s => s.startsWith(last.toLowerCase()));
      }
      const sub = before[1];
      if (sub === 'bgp' && before.length === 2) return ['summary'].filter(s => s.startsWith(last.toLowerCase()));
      if (sub === 'interfaces' && before.length === 2) return ['brief',...ifaceNames()].filter(s => s.toLowerCase().startsWith(last.toLowerCase()));
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

  global.RouterIosXr = { handleCommand, complete, restoreBgpSessions };
})(window);

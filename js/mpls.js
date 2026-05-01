window.RouterMpls = (() => {
  'use strict';

  const _parsers = {};
  // routerId → { 'prefix/len': label }  (label=3 is implicit-null/PHP)
  const _localLabels = {};
  // routerId → [session]
  const _sessions = {};
  // routerId → [lfibEntry]
  const _lfib = {};

  function registerOsParser(os, parser) { _parsers[os] = parser; }

  function _normIf(name) {
    return (name || '').toLowerCase()
      .replace(/^gigabitethernet/i, 'gi')
      .replace(/^fastethernet/i, 'fa')
      .replace(/^tengigabitethernet/i, 'te')
      .replace(/^loopback/i, 'lo')
      .replace(/\.0$/, '');
  }

  function _ifaceMatch(a, b) {
    const an = _normIf(a), bn = _normIf(b);
    return an === bn || an.startsWith(bn) || bn.startsWith(an);
  }

  function _maskToLen(mask) {
    return (mask || '').split('.').reduce((n, o) => {
      let b = parseInt(o) | 0, c = 0;
      while (b & 0x80) { c++; b = (b << 1) & 0xff; }
      return n + c;
    }, 0);
  }

  function _networkAddr(ip, prefixLen) {
    const maskVal = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
    const n = ip.split('.').reduce((acc, o) => (acc * 256) + parseInt(o), 0) & maskVal;
    return [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF].join('.');
  }

  function _ipToInt(ip) {
    return ip.split('.').reduce((a, b) => a * 256 + parseInt(b), 0) >>> 0;
  }

  function _getMplsCfg(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return null;
    const parser = _parsers[node.os];
    if (!parser || !parser.getMplsConfig) return null;
    const cfg = window.RouterStorage.read(routerId, 'running') || '';
    return parser.getMplsConfig(cfg);
  }

  function _getIfList(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return [];
    const parser = _parsers[node.os];
    if (!parser) return [];
    const cfg = window.RouterStorage.read(routerId, 'running') || '';
    const raw = parser.getInterfaceList(cfg) || [];
    return raw.map(f => ({
      name: f.name,
      ip: f.ip,
      prefixLen: f.mask ? _maskToLen(f.mask) : (f.prefixLen != null ? f.prefixLen : 0),
    })).filter(f => f.ip);
  }

  // explicit routerId > Loopback0 IP > highest IP
  function _getLdpRouterId(routerId, mplsCfg, ifList) {
    if (mplsCfg && mplsCfg.ldpRouterId) return mplsCfg.ldpRouterId;
    const lo = ifList.find(f => /^lo/i.test(_normIf(f.name)));
    if (lo) return lo.ip;
    if (ifList.length > 0) {
      return ifList.reduce((best, f) => _ipToInt(f.ip) > _ipToInt(best.ip) ? f : best).ip;
    }
    return routerId;
  }

  // Find routerId by interface IP across all nodes
  function _findRouterByIp(ip) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    for (const node of topo.nodes) {
      const ifList = _getIfList(node.id);
      if (ifList.some(f => f.ip === ip)) return node.id;
    }
    return null;
  }

  function _computeLocalLabels(routerId) {
    const mplsCfg = _getMplsCfg(routerId);
    if (!mplsCfg) { _localLabels[routerId] = {}; return; }

    const ifList = _getIfList(routerId);
    const fecSet = new Map(); // 'prefix/len' → { prefixLen, isConnected }

    // Connected prefixes from interfaces
    ifList.forEach(f => {
      const prefix = _networkAddr(f.ip, f.prefixLen);
      const key = `${prefix}/${f.prefixLen}`;
      fecSet.set(key, { prefix, prefixLen: f.prefixLen, isConnected: true });
      // host route
      const hostKey = `${f.ip}/32`;
      if (!fecSet.has(hostKey)) {
        fecSet.set(hostKey, { prefix: f.ip, prefixLen: 32, isConnected: true });
      }
    });

    // IS-IS RIB prefixes
    if (window.RouterIsis) {
      (window.RouterIsis.getRib(routerId) || []).forEach(e => {
        const key = `${e.prefix}/${e.prefixLen}`;
        if (!fecSet.has(key)) fecSet.set(key, { prefix: e.prefix, prefixLen: e.prefixLen, isConnected: false });
      });
    }

    // OSPF RIB prefixes
    if (window.RouterOspf) {
      (window.RouterOspf.getRib(routerId) || []).forEach(e => {
        const key = `${e.prefix}/${e.prefixLen}`;
        if (!fecSet.has(key)) fecSet.set(key, { prefix: e.prefix, prefixLen: e.prefixLen, isConnected: false });
      });
    }

    // Sort FECs numerically for deterministic label assignment
    const fecs = [...fecSet.entries()].sort((a, b) => {
      const [pa, la] = a[0].split('/');
      const [pb, lb] = b[0].split('/');
      const diff = _ipToInt(pa) - _ipToInt(pb);
      return diff !== 0 ? diff : parseInt(la) - parseInt(lb);
    });

    const labels = {};
    let nextLabel = 16;
    for (const [key, info] of fecs) {
      if (info.isConnected) {
        labels[key] = 3; // implicit-null (PHP)
      } else {
        labels[key] = nextLabel++;
      }
    }
    _localLabels[routerId] = labels;
  }

  function _buildSessions() {
    // Reset sessions
    const topo = window.TOPOLOGY;
    if (!topo) return;
    topo.nodes.forEach(n => { _sessions[n.id] = []; });

    for (const link of (topo.links || [])) {
      const aId = link.a, bId = link.b;
      const aPort = link.aPort, bPort = link.bPort;

      const aCfg = _getMplsCfg(aId);
      const bCfg = _getMplsCfg(bId);
      if (!aCfg || !bCfg) continue;

      const aIf = aCfg.interfaces.find(i => _ifaceMatch(i.name, aPort));
      const bIf = bCfg.interfaces.find(i => _ifaceMatch(i.name, bPort));
      if (!aIf || !bIf) continue;
      if (!aIf.ldpEnabled || !bIf.ldpEnabled) continue;

      const aIfList = _getIfList(aId);
      const bIfList = _getIfList(bId);
      const aIfInfo = aIfList.find(f => _ifaceMatch(f.name, aPort));
      const bIfInfo = bIfList.find(f => _ifaceMatch(f.name, bPort));
      if (!aIfInfo || !bIfInfo) continue;

      const aLdpId = _getLdpRouterId(aId, aCfg, aIfList);
      const bLdpId = _getLdpRouterId(bId, bCfg, bIfList);

      _sessions[aId].push({
        ldpId: `${bLdpId}:0`,
        neighborId: bId,
        localIp: aIfInfo.ip,
        neighborIp: bIfInfo.ip,
        localIface: aPort,
      });
      _sessions[bId].push({
        ldpId: `${aLdpId}:0`,
        neighborId: aId,
        localIp: bIfInfo.ip,
        neighborIp: aIfInfo.ip,
        localIface: bPort,
      });
    }
  }

  function _findIgpNexthop(routerId, prefix, prefixLen) {
    // Check IS-IS RIB
    if (window.RouterIsis) {
      const rib = window.RouterIsis.getRib(routerId) || [];
      const entry = rib.find(e => e.prefix === prefix && e.prefixLen === prefixLen);
      if (entry && entry.nexthop) return { nexthop: entry.nexthop, iface: entry.iface || null };
    }
    // Check OSPF RIB
    if (window.RouterOspf) {
      const rib = window.RouterOspf.getRib(routerId) || [];
      const entry = rib.find(e => e.prefix === prefix && e.prefixLen === prefixLen);
      if (entry && entry.nexthop) return { nexthop: entry.nexthop, iface: entry.iface || null };
    }
    return null;
  }

  function _findIfaceForNexthop(routerId, nexthopIp) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    for (const link of (topo.links || [])) {
      if (link.a === routerId) {
        const bIfList = _getIfList(link.b);
        if (bIfList.some(f => f.ip === nexthopIp)) return link.aPort;
      }
      if (link.b === routerId) {
        const aIfList = _getIfList(link.a);
        if (aIfList.some(f => f.ip === nexthopIp)) return link.bPort;
      }
    }
    return null;
  }

  function _computeLFIB(routerId) {
    const mplsCfg = _getMplsCfg(routerId);
    if (!mplsCfg) { _lfib[routerId] = []; return; }

    const localLbls = _localLabels[routerId] || {};
    const entries = [];

    for (const [fec, inLabel] of Object.entries(localLbls)) {
      if (inLabel === 3) continue; // connected/PHP: local delivery only

      const [prefix, lenStr] = fec.split('/');
      const prefixLen = parseInt(lenStr);

      const igp = _findIgpNexthop(routerId, prefix, prefixLen);
      if (!igp || !igp.nexthop) continue;

      const nbId = _findRouterByIp(igp.nexthop);
      if (!nbId) continue;

      const nbLabels = _localLabels[nbId] || {};
      const outLabel = nbLabels[fec];
      if (outLabel === undefined) continue;

      let iface = igp.iface || _findIfaceForNexthop(routerId, igp.nexthop);

      const action = outLabel === 3 ? 'pop' : 'swap';
      const outLabelStr = outLabel === 3 ? 'Pop Label' : String(outLabel);

      entries.push({
        inLabel,
        outLabel: outLabelStr,
        prefix: fec,
        action,
        iface: iface || '-',
        nexthop: igp.nexthop,
      });
    }

    _lfib[routerId] = entries;
  }

  function recalculate(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    topo.nodes.forEach(n => { _computeLocalLabels(n.id); });
    _buildSessions();
    topo.nodes.forEach(n => { _computeLFIB(n.id); });
  }

  function restoreAll() { recalculate(); }

  function getNeighbors(routerId) {
    return (_sessions[routerId] || []).map(s => ({
      ldpId: s.ldpId,
      neighborId: s.neighborId,
      localIp: s.localIp,
      neighborIp: s.neighborIp,
      iface: s.localIface,
      state: 'Oper',
      uptime: '1d00h',
    }));
  }

  function getBindings(routerId) {
    const local = _localLabels[routerId] || {};
    // Build remote bindings from sessions
    const sessions = _sessions[routerId] || [];
    return Object.entries(local).map(([fec, label]) => {
      const remoteBindings = [];
      for (const s of sessions) {
        const nbLabels = _localLabels[s.neighborId] || {};
        if (nbLabels[fec] !== undefined) {
          remoteBindings.push({
            lsr: s.ldpId,
            label: nbLabels[fec] === 3 ? 'imp-null' : String(nbLabels[fec]),
          });
        }
      }
      return {
        fec,
        localLabel: label === 3 ? 'imp-null' : String(label),
        remoteBindings,
      };
    });
  }

  function getForwardingTable(routerId) {
    return _lfib[routerId] || [];
  }

  return { registerOsParser, recalculate, restoreAll, getNeighbors, getBindings, getForwardingTable };
})();

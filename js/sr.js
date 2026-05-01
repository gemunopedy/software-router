window.RouterSr = (() => {
  'use strict';

  const _parsers = {};
  // routerId → { srEnabled, igpType, srgb:{base,end}, prefixSids:{'prefix/len':index} }
  const _srCfg = {};
  // 'prefix/len' → { routerId, index, label, valid }
  const _srDb = {};
  // routerId → [{ prefix, inLabel, action, outLabel, nexthop, iface, nhRouterId }]
  const _srLfib = {};

  function registerOsParser(os, parser) { _parsers[os] = parser; }

  function _normIf(name) {
    return (name || '').toLowerCase()
      .replace(/^gigabitethernet/i, 'gi')
      .replace(/^fastethernet/i, 'fa')
      .replace(/^tengigabitethernet/i, 'te')
      .replace(/^loopback/i, 'lo')
      .replace(/\.0$/, '');
  }

  function _maskToLen(mask) {
    return (mask || '').split('.').reduce((n, o) => {
      let b = parseInt(o) | 0, c = 0;
      while (b & 0x80) { c++; b = (b << 1) & 0xff; }
      return n + c;
    }, 0);
  }

  function _getSrCfgForNode(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return null;
    const parser = _parsers[node.os];
    if (!parser || !parser.getSrConfig) return null;
    const cfg = window.RouterStorage.read(routerId, 'running') || '';
    return parser.getSrConfig(cfg);
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

  function _collectSrConfigs() {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    // clear existing
    Object.keys(_srCfg).forEach(k => delete _srCfg[k]);
    topo.nodes.forEach(n => {
      const cfg = _getSrCfgForNode(n.id);
      if (cfg) _srCfg[n.id] = cfg;
    });
  }

  function _buildSrDb() {
    Object.keys(_srDb).forEach(k => delete _srDb[k]);

    // index → routerIds to detect duplicate SIDs across nodes
    const indexToRouters = {};

    for (const [routerId, cfg] of Object.entries(_srCfg)) {
      if (!cfg.srEnabled) continue;
      for (const [prefix, index] of Object.entries(cfg.prefixSids || {})) {
        if (!indexToRouters[index]) indexToRouters[index] = [];
        indexToRouters[index].push(routerId);
        const label = cfg.srgb.base + index;
        if (_srDb[prefix]) {
          _srDb[prefix].valid = false; // duplicate prefix
        } else {
          _srDb[prefix] = { routerId, index, label, valid: true };
        }
      }
    }

    // Mark duplicate indexes (same index, different routers) as invalid
    for (const [index, routerIds] of Object.entries(indexToRouters)) {
      if (routerIds.length > 1) {
        for (const entry of Object.values(_srDb)) {
          if (routerIds.includes(entry.routerId) && entry.index === parseInt(index)) {
            entry.valid = false;
          }
        }
      }
    }
  }

  function _getIgpNexthop(routerId, prefix, prefixLen, igpType) {
    const searchIsis = () => {
      if (!window.RouterIsis) return null;
      const e = (window.RouterIsis.getRib(routerId) || [])
        .find(r => r.prefix === prefix && r.prefixLen === prefixLen);
      return e ? e.nexthop : null;
    };
    const searchOspf = () => {
      if (!window.RouterOspf) return null;
      const e = (window.RouterOspf.getRib(routerId) || [])
        .find(r => r.prefix === prefix && r.prefixLen === prefixLen);
      return e ? e.nexthop : null;
    };

    if (igpType === 'isis') return searchIsis() || searchOspf();
    if (igpType === 'ospf') return searchOspf() || searchIsis();
    return searchIsis() || searchOspf();
  }

  function _resolveNhRouterId(nexthopIp, fromRouterId) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    for (const link of (topo.links || [])) {
      if (link.a === fromRouterId) {
        if (_getIfList(link.b).some(f => f.ip === nexthopIp)) return link.b;
      }
      if (link.b === fromRouterId) {
        if (_getIfList(link.a).some(f => f.ip === nexthopIp)) return link.a;
      }
    }
    return null;
  }

  function _findIfaceForNexthop(routerId, nexthopIp) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    for (const link of (topo.links || [])) {
      if (link.a === routerId) {
        if (_getIfList(link.b).some(f => f.ip === nexthopIp)) return link.aPort;
      }
      if (link.b === routerId) {
        if (_getIfList(link.a).some(f => f.ip === nexthopIp)) return link.bPort;
      }
    }
    return null;
  }

  function _isDirectlyAdjacent(routerId, nhRouterId) {
    const topo = window.TOPOLOGY;
    if (!topo) return false;
    return (topo.links || []).some(link =>
      (link.a === routerId && link.b === nhRouterId) ||
      (link.b === routerId && link.a === nhRouterId)
    );
  }

  function _computeSrLfib(routerId) {
    const cfg = _srCfg[routerId];
    if (!cfg || !cfg.srEnabled) { _srLfib[routerId] = []; return; }

    const localSrgb = cfg.srgb;
    const entries = [];

    for (const [prefix, entry] of Object.entries(_srDb)) {
      if (!entry.valid) continue;
      if (entry.routerId === routerId) continue;

      const [pfx, lenStr] = prefix.split('/');
      const prefixLen = parseInt(lenStr);

      const inLabel = localSrgb.base + entry.index;

      const nexthopIp = _getIgpNexthop(routerId, pfx, prefixLen, cfg.igpType);
      if (!nexthopIp) continue;

      const nhRouterId = _resolveNhRouterId(nexthopIp, routerId);
      if (!nhRouterId) continue;

      const iface = _findIfaceForNexthop(routerId, nexthopIp) || '-';

      const isPhp = _isDirectlyAdjacent(routerId, nhRouterId);
      let action, outLabel;
      if (isPhp) {
        action = 'pop';
        outLabel = 3;
      } else {
        const nhCfg = _srCfg[nhRouterId];
        const nhSrgb = (nhCfg && nhCfg.srgb) ? nhCfg.srgb : localSrgb;
        action = 'swap';
        outLabel = nhSrgb.base + entry.index;
      }

      entries.push({ prefix, inLabel, action, outLabel, nexthop: nexthopIp, iface, nhRouterId });
    }

    _srLfib[routerId] = entries;
  }

  function recalculate() {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    _collectSrConfigs();
    _buildSrDb();
    topo.nodes.forEach(n => _computeSrLfib(n.id));
  }

  function restoreAll() { recalculate(); }

  function getSrState(routerId) {
    const cfg = _srCfg[routerId];
    return {
      srEnabled: cfg ? cfg.srEnabled : false,
      igpType: cfg ? cfg.igpType : null,
      srgb: cfg ? cfg.srgb : { base: 16000, end: 23999 },
      prefixSids: cfg ? (cfg.prefixSids || {}) : {},
    };
  }

  function getSrLfib(routerId) {
    return _srLfib[routerId] || [];
  }

  function getSrLabelBlock(routerId) {
    const cfg = _srCfg[routerId];
    const srgb = (cfg && cfg.srgb) ? cfg.srgb : { base: 16000, end: 23999 };
    const allocated = Object.values(_srDb).filter(e => e.routerId === routerId && e.valid).length;
    return { base: srgb.base, end: srgb.end, size: srgb.end - srgb.base + 1, allocated };
  }

  function getSrDb() {
    return Object.entries(_srDb).map(([prefix, e]) => ({ prefix, ...e }));
  }

  return { registerOsParser, recalculate, restoreAll, getSrState, getSrLfib, getSrLabelBlock, getSrDb };
})();

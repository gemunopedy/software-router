window.RouterMulticast = (() => {
  'use strict';

  const _parsers = {};
  const _neighbors = {}; // routerId → [{neighborId, neighborIp, localIface, remoteIface, establishedAt}]
  const _mrib = {};      // routerId → [{group, rp, iif, oifList, rpf}]
  const _neighborEstablished = {}; // key=`${routerA}:${routerB}:${portA}` → timestamp

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

  function _ipToInt(ip) {
    return (ip || '0.0.0.0').split('.').reduce((a, b) => (a * 256 + parseInt(b)) >>> 0, 0) >>> 0;
  }

  function _ipInRange(ip, prefix, prefixLen) {
    const maskVal = prefixLen === 0 ? 0 : ((0xFFFFFFFF << (32 - prefixLen)) >>> 0);
    return (_ipToInt(ip) & maskVal) === (_ipToInt(prefix) & maskVal);
  }

  function _getMulticastCfg(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return null;
    const parser = _parsers[node.os];
    if (!parser || !parser.getMulticastConfig) return null;
    const cfg = window.RouterStorage.read(routerId, 'running') || window.RouterStorage.read(routerId, 'startup') || '';
    return parser.getMulticastConfig(cfg);
  }

  function _getIfList(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return [];
    const parser = _parsers[node.os];
    if (!parser || !parser.getInterfaceList) return [];
    const cfg = window.RouterStorage.read(routerId, 'running') || '';
    const raw = parser.getInterfaceList(cfg) || [];
    return raw.map(f => ({
      name: f.name,
      ip: f.ip,
      prefixLen: f.mask ? _maskToLen(f.mask) : (f.prefixLen != null ? f.prefixLen : 0),
    })).filter(f => f.ip);
  }

  function getMulticastConfig(routerId) {
    return _getMulticastCfg(routerId);
  }

  function _findRpfForIp(routerId, targetIp) {
    // Returns {iface, nexthop} for best route to targetIp, null if not found
    let bestEntry = null;
    let bestLen = -1;

    const checkRib = (rib) => {
      for (const e of (rib || [])) {
        if (_ipInRange(targetIp, e.prefix, e.prefixLen) && e.prefixLen > bestLen) {
          bestLen = e.prefixLen;
          bestEntry = e;
        }
      }
    };

    if (window.RouterOspf) checkRib(window.RouterOspf.getRib(routerId));
    if (window.RouterIsis) checkRib(window.RouterIsis.getRib(routerId));

    if (!bestEntry) return null;
    return { iface: bestEntry.iface || null, nexthop: bestEntry.nexthop };
  }

  function _isMyIp(routerId, ip) {
    const ifList = _getIfList(routerId);
    return ifList.some(f => f.ip === ip);
  }

  function recalculate() {
    const topo = window.TOPOLOGY;
    if (!topo) return;

    // Reset per-router data
    topo.nodes.forEach(n => { _neighbors[n.id] = []; _mrib[n.id] = []; });

    // Build PIM neighbor table from links
    for (const link of (topo.links || [])) {
      const aId = link.a, bId = link.b;
      const aPort = link.aPort, bPort = link.bPort;

      const aCfg = _getMulticastCfg(aId);
      const bCfg = _getMulticastCfg(bId);
      if (!aCfg || !bCfg) continue;
      if (!aCfg.enabled || !bCfg.enabled) continue;

      const aIf = aCfg.interfaces.find(i => _ifaceMatch(i.name, aPort));
      const bIf = bCfg.interfaces.find(i => _ifaceMatch(i.name, bPort));
      if (!aIf || !bIf) continue;

      const aIfList = _getIfList(aId);
      const bIfList = _getIfList(bId);
      const aIfInfo = aIfList.find(f => _ifaceMatch(f.name, aPort));
      const bIfInfo = bIfList.find(f => _ifaceMatch(f.name, bPort));

      const keyAB = `${aId}:${bId}:${aPort}`;
      const keyBA = `${bId}:${aId}:${bPort}`;

      if (!_neighborEstablished[keyAB]) _neighborEstablished[keyAB] = Date.now();
      if (!_neighborEstablished[keyBA]) _neighborEstablished[keyBA] = Date.now();

      _neighbors[aId].push({
        neighborId: bId,
        neighborIp: bIfInfo ? bIfInfo.ip : null,
        localIface: aPort,
        remoteIface: bPort,
        establishedAt: _neighborEstablished[keyAB],
      });
      _neighbors[bId].push({
        neighborId: aId,
        neighborIp: aIfInfo ? aIfInfo.ip : null,
        localIface: bPort,
        remoteIface: aPort,
        establishedAt: _neighborEstablished[keyBA],
      });
    }

    // Build (*,G) MRIB per router
    topo.nodes.forEach(routerNode => {
      const routerId = routerNode.id;
      const mCfg = _getMulticastCfg(routerId);
      if (!mCfg || !mCfg.enabled) return;

      const pimIfaces = mCfg.interfaces;
      if (pimIfaces.length === 0) return;

      // Collect RP mappings: from own config or from any router that has rpMappings
      // For each RP mapping we know about (from this router's config), compute MRIB entry
      const rpMappings = mCfg.rpMappings || [];
      if (rpMappings.length === 0) {
        // Try to find RP mappings from any node in the topology
        topo.nodes.forEach(n => {
          const nc = _getMulticastCfg(n.id);
          if (nc && nc.rpMappings && nc.rpMappings.length > 0) {
            rpMappings.push(...nc.rpMappings);
          }
        });
        // Deduplicate
        const seen = new Set();
        for (let i = rpMappings.length - 1; i >= 0; i--) {
          const key = rpMappings[i].rpIp + '/' + rpMappings[i].groupPrefix + '/' + rpMappings[i].groupPrefixLen;
          if (seen.has(key)) rpMappings.splice(i, 1);
          else seen.add(key);
        }
      }

      for (const rpMap of rpMappings) {
        const rpIp = rpMap.rpIp;
        const groupPrefix = rpMap.groupPrefix || '224.0.0.0';
        const groupPrefixLen = rpMap.groupPrefixLen != null ? rpMap.groupPrefixLen : 4;
        const groupDisplay = `${groupPrefix}/${groupPrefixLen}`;

        let iif = null;
        const isRP = _isMyIp(routerId, rpIp);

        if (!isRP) {
          const rpf = _findRpfForIp(routerId, rpIp);
          if (!rpf) continue; // Can't reach RP
          iif = rpf.iface;
        }

        const oifList = pimIfaces
          .map(i => i.name)
          .filter(n => !iif || !_ifaceMatch(n, iif));

        _mrib[routerId].push({
          group: groupDisplay,
          rp: rpIp,
          iif,
          oifList,
          rpf: rpIp,
        });
      }
    });
  }

  function restoreAll() { recalculate(); }

  function getPimNeighbors(routerId) {
    return _neighbors[routerId] || [];
  }

  function getMrib(routerId) {
    return _mrib[routerId] || [];
  }

  function getRpMappings(routerId) {
    const cfg = _getMulticastCfg(routerId);
    return cfg ? (cfg.rpMappings || []) : [];
  }

  function getRpForGroup(routerId, groupIp) {
    const cfg = _getMulticastCfg(routerId);
    if (!cfg) return null;
    let best = null, bestLen = -1;
    for (const m of (cfg.rpMappings || [])) {
      if (_ipInRange(groupIp, m.groupPrefix, m.groupPrefixLen) && m.groupPrefixLen > bestLen) {
        best = m.rpIp;
        bestLen = m.groupPrefixLen;
      }
    }
    return best;
  }

  return { registerOsParser, recalculate, restoreAll, getPimNeighbors, getMrib, getRpMappings, getRpForGroup, getMulticastConfig };
})();

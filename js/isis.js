window.RouterIsis = (() => {
  'use strict';

  const _parsers = {};
  const _rib = {}; // routerId → [{prefix, prefixLen, nexthop, metric, level}]

  function registerOsParser(os, parser) {
    _parsers[os] = parser;
  }

  function _normIf(name) {
    return (name || '').toLowerCase()
      .replace(/^gigabitethernet/i, 'gi')
      .replace(/^fastethernet/i, 'fa')
      .replace(/^tengigabitethernet/i, 'te')
      .replace(/^loopback/i, 'lo');
  }

  function _ifaceMatch(a, b) {
    const an = _normIf(a), bn = _normIf(b);
    return an === bn || an.startsWith(bn) || bn.startsWith(an);
  }

  function _netToSysId(net) {
    if (!net) return null;
    // NET format: 49.0001.0000.0000.0001.00 → sysId = 0000.0000.0001
    const parts = net.split('.');
    if (parts.length < 5) return null;
    return parts.slice(2, 5).join('.');
  }

  function _networkAddr(ip, prefixLen) {
    const maskVal = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
    const n = ip.split('.').reduce((acc, o) => (acc * 256) + parseInt(o), 0) & maskVal;
    return [(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF].join('.');
  }

  function _maskToLen(mask) {
    return (mask || '').split('.').reduce((n, o) => {
      let b = parseInt(o) | 0, c = 0;
      while (b & 0x80) { c++; b = (b << 1) & 0xff; }
      return n + c;
    }, 0);
  }

  function _getIsisCfg(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return null;
    const parser = _parsers[node.os];
    if (!parser) return null;
    const cfg = window.RouterStorage.read(routerId, 'running') || '';
    return parser.getIsisConfig(cfg);
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

  // Build IS-IS adjacency graph. Returns Map<routerId, [edges]>
  function _buildGraph() {
    const topo = window.TOPOLOGY;
    if (!topo) return new Map();

    const graph = new Map();
    topo.nodes.forEach(n => graph.set(n.id, []));

    for (const link of (topo.links || [])) {
      const aId = link.a, bId = link.b;
      const aPort = link.aPort, bPort = link.bPort;

      const aCfg = _getIsisCfg(aId);
      const bCfg = _getIsisCfg(bId);
      if (!aCfg || !bCfg) continue;
      if (!aCfg.net || !bCfg.net) continue;

      const aIf = aCfg.interfaces.find(i => _ifaceMatch(i.name, aPort));
      const bIf = bCfg.interfaces.find(i => _ifaceMatch(i.name, bPort));
      if (!aIf || !bIf) continue;

      if (aIf.passive || bIf.passive) continue;

      const aIfList = _getIfList(aId);
      const bIfList = _getIfList(bId);
      const aIfInfo = aIfList.find(f => _ifaceMatch(f.name, aPort));
      const bIfInfo = bIfList.find(f => _ifaceMatch(f.name, bPort));

      graph.get(aId).push({
        neighbor: bId,
        aIface: aPort,
        bIface: bPort,
        metric: aIf.metric,
        remoteIp: bIfInfo ? bIfInfo.ip : null,
        localIp: aIfInfo ? aIfInfo.ip : null,
      });
      graph.get(bId).push({
        neighbor: aId,
        aIface: bPort,
        bIface: aPort,
        metric: bIf.metric,
        remoteIp: aIfInfo ? aIfInfo.ip : null,
        localIp: bIfInfo ? bIfInfo.ip : null,
      });
    }

    return graph;
  }

  // Dijkstra SPF
  function _spf(graph, sourceId) {
    const dist = new Map();
    const visited = new Set();
    const parent = new Map();

    graph.forEach((_, id) => dist.set(id, Infinity));
    dist.set(sourceId, 0);

    while (true) {
      let u = null, uDist = Infinity;
      dist.forEach((d, id) => {
        if (!visited.has(id) && d < uDist) { u = id; uDist = d; }
      });
      if (u === null || uDist === Infinity) break;
      visited.add(u);

      const edges = graph.get(u) || [];
      for (const edge of edges) {
        const v = edge.neighbor;
        if (visited.has(v)) continue;
        const alt = uDist + edge.metric;
        if (alt < dist.get(v)) {
          dist.set(v, alt);
          if (u === sourceId) {
            parent.set(v, { firstHopIp: edge.remoteIp, firstHopIface: edge.aIface });
          } else {
            parent.set(v, parent.get(u));
          }
        }
      }
    }

    return { dist, parent };
  }

  function _computeRoutes(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];

    const graph = _buildGraph();
    const { dist, parent } = _spf(graph, routerId);

    const myCfg = _getIsisCfg(routerId);
    const isType = myCfg ? (myCfg.isType || 'level-1-2') : 'level-1-2';
    const levelNum = (isType.includes('2')) ? 2 : 1;

    const routes = [];

    dist.forEach((d, nodeId) => {
      if (nodeId === routerId || d === Infinity) return;
      const p = parent.get(nodeId);
      if (!p || !p.firstHopIp) return;

      const nodeCfg = _getIsisCfg(nodeId);
      if (!nodeCfg) return;
      const nodeIfList = _getIfList(nodeId);

      nodeCfg.interfaces.forEach(isisIf => {
        const ifInfo = nodeIfList.find(f => _ifaceMatch(f.name, isisIf.name));
        if (!ifInfo || !ifInfo.ip) return;
        const prefix = _networkAddr(ifInfo.ip, ifInfo.prefixLen);
        routes.push({
          prefix,
          prefixLen: ifInfo.prefixLen,
          nexthop: p.firstHopIp,
          metric: d,
          level: levelNum,
        });
      });
    });

    return routes;
  }

  function recalculate(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    topo.nodes.forEach(n => {
      const cfg = _getIsisCfg(n.id);
      if (!cfg) { _rib[n.id] = []; return; }
      _rib[n.id] = _computeRoutes(n.id);
    });
  }

  function restoreAll() {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    topo.nodes.forEach(n => {
      const cfg = _getIsisCfg(n.id);
      if (!cfg) { _rib[n.id] = []; return; }
      _rib[n.id] = _computeRoutes(n.id);
    });
  }

  function getRib(routerId) {
    return _rib[routerId] || [];
  }

  function getAdjacencies(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const graph = _buildGraph();
    const edges = graph.get(routerId) || [];
    const myCfg = _getIsisCfg(routerId);
    const isType = myCfg ? (myCfg.isType || 'level-1-2') : 'level-1-2';
    const levelNum = (isType.includes('2')) ? 2 : 1;

    return edges.map(edge => {
      const neighborCfg = _getIsisCfg(edge.neighbor);
      const sysId = neighborCfg ? (_netToSysId(neighborCfg.net) || edge.neighbor) : edge.neighbor;
      return {
        sysId,
        ifaceName: edge.aIface,
        remoteIp: edge.remoteIp,
        metric: edge.metric,
        level: levelNum,
        state: 'Up',
      };
    });
  }

  function getDatabase() {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const result = [];
    topo.nodes.forEach(n => {
      const cfg = _getIsisCfg(n.id);
      if (!cfg) return;
      const sysId = _netToSysId(cfg.net) || n.id;
      const lspId = `${sysId}.00-00`;
      const seq = '0x00000001';
      const hash = n.id.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
      const checksum = '0x' + (Math.abs(hash) % 0xFFFF).toString(16).padStart(4, '0');
      result.push({ lspId, seq, checksum, lifetime: 1199, routerId: n.id });
    });
    return result;
  }

  return { registerOsParser, recalculate, restoreAll, getRib, getAdjacencies, getDatabase };
})();

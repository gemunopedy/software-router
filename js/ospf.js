window.RouterOspf = (() => {
  'use strict';

  const _parsers = {};
  const _rib = {}; // routerId → [{prefix, prefixLen, nexthop, metric, area}]

  function registerOsParser(os, parser) {
    _parsers[os] = parser;
  }

  // '0' → '0.0.0.0', '1' → '0.0.0.1', already-dotted → as-is
  function _normalizeArea(areaId) {
    if (areaId == null) return '0.0.0.0';
    const s = String(areaId).trim();
    if (s.includes('.')) return s;
    const n = parseInt(s, 10);
    if (isNaN(n)) return s;
    return [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF].join('.');
  }

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

  function _getOspfCfg(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return null;
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return null;
    const parser = _parsers[node.os];
    if (!parser) return null;
    const cfg = window.RouterStorage.read(routerId, 'running') || '';
    return parser.getOspfConfig(cfg);
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

  // explicit routerId > Loopback0 IP > max IP
  function _getRouterId(routerId, ospfCfg, ifList) {
    if (ospfCfg && ospfCfg.routerId) return ospfCfg.routerId;
    const lo = ifList.find(f => /^lo/i.test(_normIf(f.name)));
    if (lo) return lo.ip;
    if (ifList.length > 0) {
      const toInt = ip => ip.split('.').reduce((a, b) => a * 256 + parseInt(b), 0);
      return ifList.reduce((best, f) => toInt(f.ip) > toInt(best.ip) ? f : best).ip;
    }
    return routerId;
  }

  function _buildGraph() {
    const topo = window.TOPOLOGY;
    if (!topo) return new Map();

    const graph = new Map();
    topo.nodes.forEach(n => graph.set(n.id, []));

    for (const link of (topo.links || [])) {
      const aId = link.a, bId = link.b;
      const aPort = link.aPort, bPort = link.bPort;

      const aCfg = _getOspfCfg(aId);
      const bCfg = _getOspfCfg(bId);
      if (!aCfg || !bCfg) continue;

      let aOspfIf = null, aOspfArea = null;
      for (const [areaId, areaData] of Object.entries(aCfg.areas)) {
        const iface = areaData.interfaces.find(i => _ifaceMatch(i.name, aPort));
        if (iface) { aOspfIf = iface; aOspfArea = areaId; break; }
      }

      let bOspfIf = null, bOspfArea = null;
      for (const [areaId, areaData] of Object.entries(bCfg.areas)) {
        const iface = areaData.interfaces.find(i => _ifaceMatch(i.name, bPort));
        if (iface) { bOspfIf = iface; bOspfArea = areaId; break; }
      }

      if (!aOspfIf || !bOspfIf) continue;
      if (aOspfIf.passive || bOspfIf.passive) continue;
      if (_normalizeArea(aOspfArea) !== _normalizeArea(bOspfArea)) continue;

      const aIfList = _getIfList(aId);
      const bIfList = _getIfList(bId);
      const aIfInfo = aIfList.find(f => _ifaceMatch(f.name, aPort));
      const bIfInfo = bIfList.find(f => _ifaceMatch(f.name, bPort));
      if (!aIfInfo || !bIfInfo) continue;

      const area = _normalizeArea(aOspfArea);

      graph.get(aId).push({
        neighbor: bId,
        aIface: aPort,
        bIface: bPort,
        cost: aOspfIf.cost != null ? aOspfIf.cost : 1,
        remoteIp: bIfInfo.ip,
        localIp: aIfInfo.ip,
        area,
      });
      graph.get(bId).push({
        neighbor: aId,
        aIface: bPort,
        bIface: aPort,
        cost: bOspfIf.cost != null ? bOspfIf.cost : 1,
        remoteIp: aIfInfo.ip,
        localIp: bIfInfo.ip,
        area,
      });
    }

    return graph;
  }

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

      for (const edge of (graph.get(u) || [])) {
        const v = edge.neighbor;
        if (visited.has(v)) continue;
        const alt = uDist + edge.cost;
        if (alt < dist.get(v)) {
          dist.set(v, alt);
          if (u === sourceId) {
            parent.set(v, { firstHopIp: edge.remoteIp, firstHopIface: edge.aIface, area: edge.area });
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
    const routes = [];

    dist.forEach((d, nodeId) => {
      if (nodeId === routerId || d === Infinity) return;
      const p = parent.get(nodeId);
      if (!p || !p.firstHopIp) return;

      const nodeCfg = _getOspfCfg(nodeId);
      if (!nodeCfg) return;
      const nodeIfList = _getIfList(nodeId);

      for (const [areaId, areaData] of Object.entries(nodeCfg.areas)) {
        for (const ospfIf of areaData.interfaces) {
          const ifInfo = nodeIfList.find(f => _ifaceMatch(f.name, ospfIf.name));
          if (!ifInfo || !ifInfo.ip) continue;
          const prefix = _networkAddr(ifInfo.ip, ifInfo.prefixLen);
          routes.push({
            prefix,
            prefixLen: ifInfo.prefixLen,
            nexthop: p.firstHopIp,
            metric: d,
            area: p.area || _normalizeArea(areaId),
          });
        }
      }
    });

    return routes;
  }

  function recalculate(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    topo.nodes.forEach(n => {
      const cfg = _getOspfCfg(n.id);
      _rib[n.id] = cfg ? _computeRoutes(n.id) : [];
    });
  }

  function restoreAll() {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    topo.nodes.forEach(n => {
      const cfg = _getOspfCfg(n.id);
      _rib[n.id] = cfg ? _computeRoutes(n.id) : [];
    });
  }

  function getRib(routerId) {
    return _rib[routerId] || [];
  }

  function getNeighbors(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const graph = _buildGraph();
    const edges = graph.get(routerId) || [];
    return edges.map(edge => {
      const neighborCfg = _getOspfCfg(edge.neighbor);
      const neighborIfList = _getIfList(edge.neighbor);
      const neighborRouterId = neighborCfg
        ? _getRouterId(edge.neighbor, neighborCfg, neighborIfList)
        : edge.neighbor;
      return {
        routerId: neighborRouterId,
        routerIp: edge.remoteIp,
        ifaceName: edge.aIface,
        area: edge.area,
        state: 'Full',
        cost: edge.cost,
      };
    });
  }

  function getDatabase(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const result = [];
    const graph = _buildGraph();
    topo.nodes.forEach(n => {
      const cfg = _getOspfCfg(n.id);
      if (!cfg) return;
      const ifList = _getIfList(n.id);
      const rid = _getRouterId(n.id, cfg, ifList);
      const hash = rid.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
      const checksum = '0x' + (Math.abs(hash) % 0xFFFF).toString(16).padStart(4, '0');
      const edges = graph.get(n.id) || [];
      result.push({
        lsId: rid,
        type: 'Router',
        routerId: rid,
        seq: '0x80000001',
        age: 1,
        checksum,
        linkCount: edges.length,
      });
    });
    return result;
  }

  return { registerOsParser, recalculate, restoreAll, getRib, getNeighbors, getDatabase };
})();

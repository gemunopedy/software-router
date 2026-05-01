// IPv6 エンジン（ブラウザ完結型）
// 公開: window.RouterIpv6 = { registerOsParser, getInterfaceAddrs, getNdpNeighbors, getIpv6Routes, canonIpv6, formatIpv6, networkIpv6 }
window.RouterIpv6 = (() => {
  'use strict';

  const _parsers = {};

  // --- IPv6 BigInt utilities ---

  function parseIpv6(str) {
    const s = (str || '').toLowerCase().trim();
    const halves = s.split('::');
    let groups;
    if (halves.length === 2) {
      const l = halves[0] ? halves[0].split(':') : [];
      const r = halves[1] ? halves[1].split(':') : [];
      const missing = 8 - l.length - r.length;
      groups = [...l, ...Array(missing).fill('0'), ...r];
    } else {
      groups = s.split(':');
    }
    return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || '0', 16)), 0n);
  }

  function formatIpv6(big) {
    const groups = [];
    for (let i = 7; i >= 0; i--) {
      groups.unshift(((big >> BigInt(i * 16)) & 0xffffn).toString(16));
    }
    let best = { start: -1, len: 0 }, cur = { start: -1, len: 0 };
    groups.forEach((g, i) => {
      if (g === '0') {
        if (cur.start < 0) cur = { start: i, len: 1 };
        else cur.len++;
        if (cur.len > best.len) best = { ...cur };
      } else {
        cur = { start: -1, len: 0 };
      }
    });
    if (best.len > 1) {
      const left = groups.slice(0, best.start).join(':');
      const right = groups.slice(best.start + best.len).join(':');
      return (left ? left + '::' : '::') + right;
    }
    return groups.join(':');
  }

  function canonIpv6(str) {
    try { return formatIpv6(parseIpv6(str)); } catch (e) { return (str || '::').toLowerCase(); }
  }

  function networkIpv6(addr, prefixLen) {
    const addrBig = parseIpv6(addr);
    if (prefixLen === 0) return 0n;
    if (prefixLen >= 128) return addrBig;
    const shift = BigInt(128 - prefixLen);
    const mask = ((1n << 128n) - 1n) ^ ((1n << shift) - 1n);
    return addrBig & mask;
  }

  function containsIpv6(netBig, prefixLen, addrBig) {
    if (prefixLen === 0) return true;
    if (prefixLen >= 128) return addrBig === netBig;
    const shift = BigInt(128 - prefixLen);
    const mask = ((1n << 128n) - 1n) ^ ((1n << shift) - 1n);
    return (addrBig & mask) === netBig;
  }

  // --- interface name normalization ---
  function _normIf(name) {
    return (name || '').toLowerCase()
      .replace(/^gigabitethernet/i, 'gi')
      .replace(/^tengigabitethernet/i, 'te')
      .replace(/^fastethernet/i, 'fa')
      .replace(/^loopback/i, 'lo')
      .replace(/\.0$/, '');
  }

  // --- link-local generation ---
  // fe80::<routerIdx>:<ifaceIdx>
  function _genLinkLocal(routerId, ifaceName) {
    const topo = window.TOPOLOGY;
    if (!topo) return 'fe80::1';
    const rIdx = (topo.nodes.findIndex(n => n.id === routerId) + 1) & 0xffff;
    const nums = (ifaceName || '').match(/\d+/g) || ['0'];
    const ifIdx = (parseInt(nums[nums.length - 1], 10) + 1) & 0xffff;
    return `fe80::${rIdx.toString(16)}:${ifIdx.toString(16)}`;
  }

  // --- per-router state ---

  function getInterfaceAddrs(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const node = topo.nodes.find(n => n.id === routerId);
    if (!node) return [];
    const parser = _parsers[node.os];
    if (!parser || !parser.getInterfaceAddrs) return [];
    const cfg = window.RouterStorage.read(routerId, 'running') || '';
    const ifaces = parser.getInterfaceAddrs(cfg);
    return ifaces.map(f => {
      const hasAddr = (f.ipv4 && f.ipv4.length > 0) || (f.ipv6 && f.ipv6.length > 0);
      const linkLocal = hasAddr ? _genLinkLocal(routerId, f.name) : null;
      const ipv6 = [...(f.ipv6 || [])];
      if (linkLocal && !ipv6.some(a => a.addr.toLowerCase().startsWith('fe80'))) {
        ipv6.unshift({ addr: linkLocal, prefixLen: 10, type: 'link-local' });
      }
      return { ...f, ipv6 };
    });
  }

  function getNdpNeighbors(routerId) {
    const topo = window.TOPOLOGY;
    if (!topo) return [];
    const neighbors = [];

    for (const link of (topo.links || [])) {
      let myIface, remoteId, remoteIface;
      if (link.a === routerId) {
        myIface = link.aPort;
        remoteId = link.b;
        remoteIface = link.bPort;
      } else if (link.b === routerId) {
        myIface = link.bPort;
        remoteId = link.a;
        remoteIface = link.aPort;
      } else continue;

      const remoteAddrs = getInterfaceAddrs(remoteId);
      const remoteIfaceObj = remoteAddrs.find(f => _normIf(f.name) === _normIf(remoteIface));
      if (!remoteIfaceObj || remoteIfaceObj.shutdown) continue;

      const remoteNodeIdx = topo.nodes.findIndex(n => n.id === remoteId);
      const mac = `aabb.cc${(remoteNodeIdx + 1).toString(16).padStart(2, '0')}.0100`;

      for (const { addr } of remoteIfaceObj.ipv6) {
        neighbors.push({
          addr: canonIpv6(addr),
          mac,
          state: 'REACH',
          iface: myIface,
          routerId: remoteId,
        });
      }
    }
    return neighbors;
  }

  function getIpv6Routes(routerId) {
    const ifaces = getInterfaceAddrs(routerId);
    const routes = [];

    for (const f of ifaces) {
      if (f.shutdown) continue;
      for (const { addr, prefixLen, type } of f.ipv6) {
        if (type === 'link-local') continue;
        const netBig = networkIpv6(addr, prefixLen);
        routes.push({ type: 'C', prefix: formatIpv6(netBig), prefixLen, iface: f.name, ad: 0 });
        routes.push({ type: 'L', prefix: canonIpv6(addr), prefixLen: 128, iface: f.name, ad: 0 });
      }
    }

    const topo = window.TOPOLOGY;
    const node = topo && topo.nodes.find(n => n.id === routerId);
    if (node) {
      const parser = _parsers[node.os];
      if (parser && parser.getIpv6StaticRoutes) {
        const cfg = window.RouterStorage.read(routerId, 'running') || '';
        for (const s of (parser.getIpv6StaticRoutes(cfg) || [])) {
          routes.push({ type: 'S', prefix: s.prefix, prefixLen: s.prefixLen, nexthop: s.nexthop, ad: s.ad || 1 });
        }
      }
    }

    return routes;
  }

  function registerOsParser(os, parser) { _parsers[os] = parser; }

  return {
    registerOsParser,
    getInterfaceAddrs,
    getNdpNeighbors,
    getIpv6Routes,
    canonIpv6,
    formatIpv6,
    networkIpv6,
  };
})();

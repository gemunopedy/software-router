// SRv6 v1 エンジン（ブラウザ完結型）
// 公開: window.RouterSrv6 = { registerOsParser, recalculate, restoreAll, getSidDb, getFwdTable, getLocators, getSrv6State }
window.RouterSrv6 = (() => {
  'use strict';

  const _parsers = {};
  // routerId → { srv6Enabled, igpType:'isis'|'ospf'|null, locators:[{name, prefix, prefixLen}] }
  const _cfg = {};
  // sid(canonical) → { routerId, behavior:'End', locatorName, locatorPrefix, prefixLen, valid }
  const _sidDb = {};
  // routerId → [{ locatorPrefix, prefixLen, nexthopIp, iface, nhRouterId, destRouterId }]
  const _fwdTable = {};

  function registerOsParser(os, parser) { _parsers[os] = parser; }

  // --- IPv6 ユーティリティ（RouterIpv6.parseIpv6 は未公開のためインライン実装）---
  function _parseIpv6(str) {
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

  function _normIf(name) {
    return (name || '').toLowerCase()
      .replace(/^gigabitethernet/i, 'gi')
      .replace(/^fastethernet/i, 'fa')
      .replace(/^tengigabitethernet/i, 'te')
      .replace(/^loopback/i, 'lo')
      .replace(/\.0$/, '');
  }

  // --- SRv6 設定収集 ---
  function _collectCfgs() {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    for (const node of topo.nodes) {
      const parser = _parsers[node.os];
      if (!parser || !parser.getSrv6Config) { _cfg[node.id] = null; continue; }
      const raw = window.RouterStorage.read(node.id, 'running') || '';
      _cfg[node.id] = parser.getSrv6Config(raw);
    }
  }

  // --- SID DB 構築 ---
  // End SID = locator prefix | 1  例: 2001:db8:1::/48 → 2001:db8:1::1
  function _buildSidDb() {
    Object.keys(_sidDb).forEach(k => delete _sidDb[k]);

    const topo = window.TOPOLOGY;
    if (!topo) return;

    // locator prefix の重複チェック
    const locatorCount = {};
    for (const node of topo.nodes) {
      const cfg = _cfg[node.id];
      if (!cfg || !cfg.srv6Enabled || !cfg.locators.length) continue;
      const loc = cfg.locators[0];
      // ネットワークアドレスに正規化してカウント
      const netBig = RouterIpv6.networkIpv6(loc.prefix, loc.prefixLen);
      const canonNet = RouterIpv6.formatIpv6(netBig);
      const key = `${canonNet}/${loc.prefixLen}`;
      locatorCount[key] = (locatorCount[key] || 0) + 1;
    }

    for (const node of topo.nodes) {
      const cfg = _cfg[node.id];
      if (!cfg || !cfg.srv6Enabled || !cfg.locators.length) continue;
      const loc = cfg.locators[0];
      const netBig = RouterIpv6.networkIpv6(loc.prefix, loc.prefixLen);
      const canonPrefix = RouterIpv6.formatIpv6(netBig);
      const locKey = `${canonPrefix}/${loc.prefixLen}`;
      const valid = locatorCount[locKey] === 1;

      // End SID: locator network | 1
      const endSidBig = netBig | 1n;
      const endSid = RouterIpv6.canonIpv6(RouterIpv6.formatIpv6(endSidBig));
      _sidDb[endSid] = {
        routerId: node.id,
        behavior: 'End',
        locatorName: loc.name,
        locatorPrefix: canonPrefix,
        prefixLen: loc.prefixLen,
        valid,
      };
    }
  }

  // BFS で fromId から各ルーターへの first-hop 情報を求める
  // 戻り値: Map<routerId, {routerId, localIface, remoteIface}>
  function _bfsFirstHop(fromId) {
    const topo = window.TOPOLOGY;
    const result = new Map();
    const visited = new Set([fromId]);
    const queue = [];

    for (const link of (topo.links || [])) {
      let myIface, remIface, remId;
      if (link.a === fromId) {
        myIface = link.aPort; remIface = link.bPort; remId = link.b;
      } else if (link.b === fromId) {
        myIface = link.bPort; remIface = link.aPort; remId = link.a;
      } else continue;

      if (visited.has(remId)) continue;
      visited.add(remId);
      const hop = { routerId: remId, localIface: myIface, remoteIface: remIface };
      result.set(remId, hop);
      queue.push({ routerId: remId, firstHop: hop });
    }

    while (queue.length > 0) {
      const { routerId, firstHop } = queue.shift();
      for (const link of (topo.links || [])) {
        let remId;
        if (link.a === routerId) remId = link.b;
        else if (link.b === routerId) remId = link.a;
        else continue;
        if (visited.has(remId)) continue;
        visited.add(remId);
        result.set(remId, firstHop);
        queue.push({ routerId: remId, firstHop });
      }
    }

    return result;
  }

  // --- SRv6 Forwarding Table 構築 ---
  function _buildFwdTable() {
    const topo = window.TOPOLOGY;
    if (!topo) return;
    Object.keys(_fwdTable).forEach(k => delete _fwdTable[k]);

    for (const node of topo.nodes) {
      _fwdTable[node.id] = [];
      const cfg = _cfg[node.id];
      if (!cfg || !cfg.srv6Enabled) continue;

      const firstHop = _bfsFirstHop(node.id);

      for (const other of topo.nodes) {
        if (other.id === node.id) continue;
        const otherCfg = _cfg[other.id];
        if (!otherCfg || !otherCfg.srv6Enabled || !otherCfg.locators.length) continue;

        // SID の valid チェック
        const sidEntry = Object.values(_sidDb).find(e => e.routerId === other.id);
        if (!sidEntry || !sidEntry.valid) continue;

        const hop = firstHop.get(other.id);
        if (!hop) continue;

        // 次ホップルーターの対向インタフェースの link-local アドレスを取得
        const nhAddrs = RouterIpv6.getInterfaceAddrs(hop.routerId);
        const nhIface = nhAddrs.find(f => _normIf(f.name) === _normIf(hop.remoteIface));
        const linkLocal = nhIface ? (nhIface.ipv6 || []).find(a => (a.addr || '').startsWith('fe80')) : null;
        const nexthopIp = linkLocal ? linkLocal.addr : '::';

        const loc = otherCfg.locators[0];
        const netBig = RouterIpv6.networkIpv6(loc.prefix, loc.prefixLen);
        const canonPrefix = RouterIpv6.formatIpv6(netBig);

        _fwdTable[node.id].push({
          locatorPrefix: canonPrefix,
          prefixLen: loc.prefixLen,
          nexthopIp,
          iface: hop.localIface,
          nhRouterId: hop.routerId,
          destRouterId: other.id,
        });
      }
    }
  }

  function recalculate() {
    _collectCfgs();
    _buildSidDb();
    _buildFwdTable();
  }

  function restoreAll() { recalculate(); }

  function getSidDb(routerId) {
    return Object.entries(_sidDb)
      .filter(([, e]) => !routerId || e.routerId === routerId)
      .map(([sid, e]) => ({ sid, ...e }));
  }

  function getFwdTable(routerId) {
    return _fwdTable[routerId] || [];
  }

  function getLocators(routerId) {
    const cfg = _cfg[routerId];
    return (cfg && cfg.locators) ? cfg.locators : [];
  }

  function getSrv6State(routerId) {
    const cfg = _cfg[routerId];
    return {
      srv6Enabled: cfg ? cfg.srv6Enabled : false,
      igpType: cfg ? cfg.igpType : null,
    };
  }

  return { registerOsParser, recalculate, restoreAll, getSidDb, getFwdTable, getLocators, getSrv6State };
})();

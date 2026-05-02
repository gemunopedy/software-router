// JunOS CLI エミュレーション（set スタイル設定）。
// commands.js から os === 'junos' のときに呼ばれる。
//
// 公開:
//   RouterJunos.handleCommand(parts, state, io)
//   RouterJunos.complete(line, router, state) → string[]
//   RouterJunos.restoreBgpSessions(router)
//
// config 保存形式: "set ..." の行リスト（JunOS set コマンド形式）
// 例:
//   set system host-name R3-JunOS
//   set interfaces ge-0/0/0 unit 0 family inet address 10.0.23.3/24
//   set routing-options autonomous-system 65003
//   set routing-options router-id 3.3.3.3
//   set protocols bgp group EBGP neighbor 10.0.23.2 peer-as 65002
//   set protocols bgp network 10.1.0.0/24
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

  // ---- config パーサ（set 形式） ----

  function getHostname(cfg) {
    const m = (cfg || '').match(/^set system host-name\s+(\S+)/im);
    return m ? m[1] : null;
  }

  // [{name, ip, mask, prefixLen}]
  function getInterfaces(cfg) {
    const result = [];
    const re = /^set interfaces (\S+) unit \d+ family inet address ([\d.]+)\/([\d]+)/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      const ifname = m[1];
      const ip = m[2], prefixLen = parseInt(m[3], 10);
      result.push({ name: ifname, ip, mask: _prefixToMask(prefixLen), prefixLen });
    }
    return result;
  }

  // BGP ネイバー一覧: [{ip, peerAs, groupName, localAddress}]
  function getBgpNeighbors(cfg) {
    const result = new Map(); // ip → entry
    const peerRe = /^set protocols bgp group (\S+) neighbor ([\d.]+) peer-as (\d+)/gim;
    let m;
    while ((m = peerRe.exec(cfg || ''))) {
      result.set(m[2], { groupName: m[1], ip: m[2], peerAs: parseInt(m[3], 10), localAddress: null });
    }
    // local-address
    const laRe = /^set protocols bgp group (\S+) neighbor ([\d.]+) local-address ([\d.]+)/gim;
    while ((m = laRe.exec(cfg || ''))) {
      if (result.has(m[2])) result.get(m[2]).localAddress = m[3];
    }
    return [...result.values()];
  }

  // BGP network 広報一覧: [{prefix, prefixLen}]
  function getBgpNetworks(cfg) {
    const result = [];
    const re = /^set protocols bgp network ([\d.]+)\/([\d]+)/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      result.push({ prefix: m[1], prefixLen: parseInt(m[2], 10) });
    }
    return result;
  }

  function getRoutingInstances(cfg) {
    const result = [];
    const lines = (cfg || '').split('\n');
    for (const raw of lines) {
      const t = raw.trim();
      const m = t.match(/^set routing-instances\s+(\S+)\s+instance-type\s+/i);
      if (m) {
        if (!result.find(r => r.name === m[1])) {
          result.push({ name: m[1], rd: '', importPolicies: [], exportPolicies: [], ifaces: [] });
        }
        continue;
      }
      const rdM = t.match(/^set routing-instances\s+(\S+)\s+route-distinguisher\s+(\S+)/i);
      if (rdM) {
        let r2 = result.find(r => r.name === rdM[1]);
        if (!r2) { r2 = { name: rdM[1], rd: '', importPolicies: [], exportPolicies: [], ifaces: [] }; result.push(r2); }
        r2.rd = rdM[2];
        continue;
      }
      const ifM = t.match(/^set routing-instances\s+(\S+)\s+interface\s+(\S+)/i);
      if (ifM) {
        let r2 = result.find(r => r.name === ifM[1]);
        if (!r2) { r2 = { name: ifM[1], rd: '', importPolicies: [], exportPolicies: [], ifaces: [] }; result.push(r2); }
        if (!r2.ifaces.includes(ifM[2])) r2.ifaces.push(ifM[2]);
        continue;
      }
    }
    return result;
  }

  function getBgpAs(cfg) {
    const m = (cfg || '').match(/^set routing-options autonomous-system\s+(\d+)/im);
    return m ? parseInt(m[1], 10) : 65000;
  }

  // set routing-options static route <prefix/len> next-hop <nexthop> [preference <ad>]
  function getStaticRoutes(cfg) {
    const result = [];
    const re = /^set routing-options static route ([\d.]+)\/([\d]+) next-hop ([\d.]+)(?:\s+preference\s+(\d+))?/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      result.push({ prefix: m[1], prefixLen: parseInt(m[2], 10), nexthop: m[3], ad: m[4] ? parseInt(m[4]) : 1 });
    }
    return result;
  }

  function getBgpRouterId(cfg) {
    const ridM = (cfg || '').match(/^set routing-options router-id\s+([\d.]+)/im);
    if (ridM) return ridM[1];
    // loopback
    const ifaces = getInterfaces(cfg);
    const lo = ifaces.find(f => /^lo0$/i.test(f.name));
    if (lo) return lo.ip;
    const phys = ifaces.find(f => !/^lo/i.test(f.name));
    return phys ? phys.ip : '0.0.0.0';
  }

  function topoIdx(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // ---- config 操作（set/delete 行管理） ----

  // set ラインを追加/置換する（同じプレフィックスの行があれば置換）
  function _setLine(router, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n').filter(l => l.trim() !== '');
    // newLine のキー部分（最後のキーワード群で判断: set X Y Z ...）
    // 同一 set パスの行があれば置換、なければ追加
    // キー: "set X Y Z" の X Y Z で最後の値を除いた部分
    // ただし "set interfaces IF unit N family inet address" のように値が最後に来る場合のみ置換
    const idx = lines.findIndex(l => l.trim() === newLine.trim());
    if (idx >= 0) return; // 既に存在
    lines.push(newLine.trim());
    Storage.write(router.id, 'running', lines.join('\n'));
  }

  // 特定パターンにマッチする set 行を削除
  function _deleteLines(router, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const out = cfg.split('\n').filter(l => !matchRe.test(l.trim()));
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // GARP 送信
  function _sendGarp(router, ifaceName, addr) {
    if (!Packets) return;
    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = getInterfaces(cfg);
    const idx = ifaces.findIndex(f => f.name === ifaceName);
    const ifaceIdx = idx >= 0 ? idx : 0;
    const mac = Packets.buildIfaceMac(topoIdx(router.id), ifaceIdx);
    const pkt = Packets.buildPacket({ proto: 'arp', op: 'reply', src: addr, dst: addr, srcMac: mac, targetMac: 'ff:ff:ff:ff:ff:ff' });
    const Pcap = global.RouterPcap;
    if (Pcap) { Pcap.append(router.id, pkt); if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus(); }
    if (global.RouterCapture) global.RouterCapture.emit(router.id, pkt, { iface: ifaceName });
  }

  // ---- show コマンド ----

  function showInterfaces(args, router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = getInterfaces(cfg);
    io.println('Interface               Link  Proto  Family         Address');
    ifaces.forEach(f => {
      const addr = `${f.ip}/${f.prefixLen}`;
      io.println(`${f.name.padEnd(24)}Up    Up     inet           ${addr}`);
    });
    if (ifaces.length === 0) io.println('[no interfaces configured]');
  }

  function showBgp(args, router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const asn = getBgpAs(cfg);
    const routerId = getBgpRouterId(cfg);
    const neighbors = getBgpNeighbors(cfg);
    const sub = (args[0] || '').toLowerCase();

    if (!neighbors.length && !asn) { io.println('BGP is not configured.'); return; }

    if (sub === 'summary') {
      io.println(`Groups: ${new Set(neighbors.map(n => n.groupName)).size} Peers: ${neighbors.length} Down peers: 0`);
      io.println('');
      io.println(`Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending`);
      io.println(`inet.0                 0          0          0          0          0          0`);
      io.println('');
      io.println(`Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...`);
      neighbors.forEach(n => {
        const est  = RouterBgp.isEstablished(router.id, n.ip);
        const info = RouterBgp.getSessionInfo(router.id, n.ip);
        let updown = '0';
        let statePfx = 'Idle';
        if (est && info) {
          const sec = Math.floor((Date.now() - info.establishedAt) / 1000);
          const h = Math.floor(sec / 3600), mn = Math.floor((sec % 3600) / 60), s = sec % 60;
          updown = `${String(h).padStart(2,'0')}:${String(mn).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
          const pfxCount = RouterBgp.getRib(router.id).filter(e => e.neighborIp === n.ip).length;
          statePfx = `Establ\n${' '.repeat(25)}inet.0: ${pfxCount}/${pfxCount}/${pfxCount}/0`;
        }
        io.println(`${n.ip.padEnd(25)}${String(n.peerAs).padEnd(8)}0         0         0       0 ${updown} ${statePfx}`);
      });
      return;
    }

    // show bgp (table)
    io.println(`  Autonomous system number: ${asn}`);
    io.println(`  Router ID: ${routerId}`);
    io.println('');
    io.println('inet.0: 0 destinations, 0 routes (0 active, 0 holddown, 0 hidden)');
    io.println('');
    io.println('+ = Active Route, - = Last Active, * = Both');
    io.println('');
    const rib = RouterBgp.getRib(router.id);
    if (rib.length === 0) { io.println('[no BGP routes]'); return; }
    rib.forEach(e => {
      const isSelf = e.neighborIp === 'self';
      const nh = isSelf ? 'Self' : e.nextHop;
      io.println(`${e.prefix}/${e.prefixLen}          *[BGP/${e.asPath.join(' ')}] self`);
      io.println(`                    > to ${nh}`);
    });
  }

  function showRoute(args, router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = getInterfaces(cfg);
    io.println('');
    io.println('inet.0: routes');
    io.println('');

    // すべてのルート候補を収集
    const candidates = [];
    ifaces.forEach(f => {
      const netOcts  = f.ip.split('.').map(Number);
      const maskOcts = f.mask.split('.').map(Number);
      const net = netOcts.map((b, i) => b & maskOcts[i]).join('.');
      candidates.push({ type: 'Direct', prefix: net,  prefixLen: f.prefixLen, ad: 0, metric: 0, via: f.name });
      candidates.push({ type: 'Local',  prefix: f.ip, prefixLen: 32,          ad: 0, metric: 0, via: f.name });
    });
    getStaticRoutes(cfg).forEach(e => {
      candidates.push({ type: 'Static', prefix: e.prefix, prefixLen: e.prefixLen, ad: e.ad, metric: 0, nexthop: e.nexthop });
    });
    RouterIsis.getRib(router.id).forEach(e => {
      candidates.push({ type: 'ISIS', prefix: e.prefix, prefixLen: e.prefixLen, ad: 15, metric: e.metric, nexthop: e.nexthop, level: e.level });
    });
    RouterOspf.getRib(router.id).forEach(e => {
      candidates.push({ type: 'OSPF', prefix: e.prefix, prefixLen: e.prefixLen, ad: 10, metric: e.metric, nexthop: e.nexthop });
    });
    RouterBgp.getRib(router.id).filter(e => e.selected && e.neighborIp !== 'self').forEach(e => {
      candidates.push({ type: 'BGP', prefix: e.prefix, prefixLen: e.prefixLen, ad: 20, metric: 0, nexthop: e.nextHop, asPath: e.asPath });
    });

    // AD選択後の best-route のみ表示
    RouterRib.selectBest(candidates).forEach(r => {
      if (r.type === 'Direct') {
        io.println(`${r.prefix}/${r.prefixLen}            *[Direct/0] preference 0`);
        io.println(`                    > via ${r.via}`);
      } else if (r.type === 'Local') {
        io.println(`${r.prefix}/${r.prefixLen}              *[Local/0] preference 0`);
        io.println(`                      Local via ${r.via}`);
      } else if (r.type === 'Static') {
        io.println(`${r.prefix}/${r.prefixLen}       *[Static/${r.ad}] preference ${r.ad}`);
        io.println(`                    > to ${r.nexthop}`);
      } else if (r.type === 'ISIS') {
        io.println(`${r.prefix}/${r.prefixLen}       *[IS-IS/15] preference 15 metric ${r.metric}`);
        io.println(`                    > to ${r.nexthop}`);
      } else if (r.type === 'OSPF') {
        io.println(`${r.prefix}/${r.prefixLen}       *[OSPF/10] preference 10 metric ${r.metric}`);
        io.println(`                    > to ${r.nexthop}`);
      } else if (r.type === 'BGP') {
        const path = r.asPath ? r.asPath.join(' ') : '';
        io.println(`${r.prefix}/${r.prefixLen}     *[BGP/20] preference 20 AS path: ${path}`);
        io.println(`                    > to ${r.nexthop}`);
      }
    });
  }

  function showConfig(router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const host = getHostname(cfg) || router.hostname || router.id;
    io.println(`## Last changed: ${new Date().toUTCString()}`);
    io.println('## Image timestamp: (emulated)');
    io.println('');
    io.println(`system {`);
    io.println(`    host-name ${host};`);
    io.println(`}`);
    const ifaces = getInterfaces(cfg);
    if (ifaces.length) {
      io.println('interfaces {');
      const grouped = new Map();
      ifaces.forEach(f => {
        if (!grouped.has(f.name)) grouped.set(f.name, []);
        grouped.get(f.name).push(f);
      });
      for (const [name, list] of grouped) {
        io.println(`    ${name} {`);
        io.println(`        unit 0 {`);
        io.println(`            family inet {`);
        list.forEach(f => io.println(`                address ${f.ip}/${f.prefixLen};`));
        io.println(`            }`);
        io.println(`        }`);
        io.println(`    }`);
      }
      io.println('}');
    }
    const asn = getBgpAs(cfg);
    const rid = getBgpRouterId(cfg);
    const staticRoutes = getStaticRoutes(cfg);
    const srv6Cfg = getSrv6Config(cfg);
    const roM = cfg.match(/^set routing-options/gim);
    if (roM || staticRoutes.length || srv6Cfg) {
      io.println('routing-options {');
      if (asn) io.println(`    autonomous-system ${asn};`);
      if (rid) io.println(`    router-id ${rid};`);
      if (staticRoutes.length) {
        io.println('    static {');
        staticRoutes.forEach(e => {
          const pref = e.ad !== 1 ? ` preference ${e.ad}` : '';
          io.println(`        route ${e.prefix}/${e.prefixLen} next-hop ${e.nexthop};${pref}`);
        });
        io.println('    }');
      }
      if (srv6Cfg) {
        io.println('    source-packet-routing {');
        io.println('        srv6 {');
        for (const loc of srv6Cfg.locators) {
          io.println(`            locator ${loc.name} {`);
          if (loc.prefix !== undefined) io.println(`                prefix ${loc.prefix}/${loc.prefixLen};`);
          io.println('            }');
        }
        io.println('        }');
        io.println('    }');
      }
      io.println('}');
    }
    const neighbors = getBgpNeighbors(cfg);
    const networks  = getBgpNetworks(cfg);
    const ospfCfg = getOspfConfig(cfg);
    const mplsCfg2 = getMplsConfig(cfg);
    if (neighbors.length || networks.length || ospfCfg || mplsCfg2) {
      io.println('protocols {');
      io.println('    bgp {');
      // group by groupName
      const groups = new Map();
      neighbors.forEach(n => {
        if (!groups.has(n.groupName)) groups.set(n.groupName, []);
        groups.get(n.groupName).push(n);
      });
      for (const [gname, list] of groups) {
        io.println(`        group ${gname} {`);
        io.println(`            type external;`);
        list.forEach(n => {
          io.println(`            neighbor ${n.ip} {`);
          io.println(`                peer-as ${n.peerAs};`);
          if (n.localAddress) io.println(`                local-address ${n.localAddress};`);
          io.println(`            }`);
        });
        io.println(`        }`);
      }
      networks.forEach(n => io.println(`        network ${n.prefix}/${n.prefixLen};`));
      if (neighbors.length || networks.length) { io.println('    }'); }
      if (ospfCfg) {
        io.println('    ospf {');
        for (const [areaId, ifArr] of Object.entries(ospfCfg.areas)) {
          io.println(`        area ${areaId} {`);
          ifArr.forEach(ifObj => {
            io.println(`            interface ${ifObj.name} {`);
            if (ifObj.props) {
              const metM = ifObj.props.match(/metric\s+(\d+)/i);
              if (metM) io.println(`                metric ${metM[1]};`);
              if (/passive/i.test(ifObj.props)) io.println('                passive;');
            }
            io.println('            }');
          });
          io.println('        }');
        }
        io.println('    }');
      }
      if (mplsCfg2) {
        const mplsIfs = mplsCfg2.interfaces.filter(i => i.mplsEnabled);
        const ldpIfs  = mplsCfg2.interfaces.filter(i => i.ldpEnabled);
        if (mplsIfs.length) {
          io.println('    mpls {');
          mplsIfs.forEach(i => io.println(`        interface ${i.name};`));
          io.println('    }');
        }
        if (ldpIfs.length) {
          io.println('    ldp {');
          ldpIfs.forEach(i => io.println(`        interface ${i.name};`));
          io.println('    }');
        }
      }
      io.println('}');
    }
    // class-of-service ブロックを show configuration に追加
    const cosCfg = RouterQos.parseJunosCoS(cfg);
    const hasCoS = cosCfg.classifiers.length || cosCfg.schedulers.length || cosCfg.schedulerMaps.length || cosCfg.ifaceSchedulerMaps.length;
    if (hasCoS) {
      // set 形式でそのまま出力
      const cosLines = (cfg || '').split('\n').filter(l => /^set class-of-service\s+/i.test(l.trim()));
      cosLines.forEach(l => io.println(l));
    }
  }

  function getOspfConfig(cfg) {
    const areas = {};
    const re = /^set protocols ospf area (\S+) interface (\S+)(.*)?/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      const areaId = m[1], ifname = m[2], extra = (m[3] || '').trim();
      if (!areas[areaId]) areas[areaId] = [];
      const existing = areas[areaId].find(e => e.name === ifname);
      if (existing) {
        if (extra) existing.props = extra;
      } else {
        areas[areaId].push({ name: ifname, props: extra });
      }
    }
    if (Object.keys(areas).length === 0) return null;
    return { areas };
  }

  function getSrConfig(cfg) {
    const lines = (cfg || '').split('\n');

    // Check for SRGB configuration
    let srEnabled = false, srgbBase = 16000, srgbEnd = 23999;
    let igpType = null;

    for (const l of lines) {
      // set protocols isis source-packet-routing srgb start-label N index-range M
      const srgbM = l.match(/^set protocols isis source-packet-routing srgb start-label\s+(\d+)\s+index-range\s+(\d+)/i);
      if (srgbM) {
        srgbBase = parseInt(srgbM[1]);
        srgbEnd = srgbBase + parseInt(srgbM[2]) - 1;
        srEnabled = true;
        igpType = 'isis';
        continue;
      }
      // set protocols isis source-packet-routing (without srgb → SR enabled with defaults)
      if (/^set protocols isis source-packet-routing\b/i.test(l)) {
        srEnabled = true;
        igpType = 'isis';
        continue;
      }
    }

    if (!srEnabled) return null;

    // Collect prefix-sids from loopback interfaces
    // set protocols isis interface lo0.0 level 2 prefix-sid index N
    const prefixSids = {};
    const ifaces = getInterfaces(cfg);
    for (const l of lines) {
      const m = l.match(/^set protocols isis interface\s+(\S+)\s+level\s+\d+\s+prefix-sid\s+index\s+(\d+)/i);
      if (!m) continue;
      const ifName = m[1];
      const index = parseInt(m[2]);
      // Find IP for this interface
      const iface = ifaces.find(f => f.name === ifName || f.name === ifName.replace(/\.0$/, ''));
      if (iface) prefixSids[`${iface.ip}/32`] = index;
    }

    return { srEnabled, igpType, srgb: { base: srgbBase, end: srgbEnd }, prefixSids };
  }

  function getMplsConfig(cfg) {
    const lines = (cfg || '').split('\n');
    const mpls = new Set(), ldp = new Set();
    for (const l of lines) {
      const mm = l.match(/^set protocols mpls interface\s+(\S+)/i);
      if (mm) mpls.add(mm[1]);
      const lm = l.match(/^set protocols ldp interface\s+(\S+)/i);
      if (lm) ldp.add(lm[1]);
    }
    const allIfs = new Set([...mpls, ...ldp]);
    if (!allIfs.size) return null;
    const interfaces = [...allIfs].map(name => ({
      name,
      mplsEnabled: mpls.has(name),
      ldpEnabled: ldp.has(name),
    }));
    return { interfaces, ldpRouterId: null };
  }

  // --- SRv6 設定パーサ ---
  // 設定形式: set routing-options source-packet-routing srv6 locator <NAME> prefix <P/L>
  //           set protocols isis source-packet-routing srv6 locator <NAME>
  function getSrv6Config(cfg) {
    const lines = (cfg || '').split('\n');
    let srv6Enabled = false;
    let igpType = null;
    const locatorMap = new Map();

    for (const l of lines) {
      // ロケーター prefix
      const locM = l.match(/^set routing-options source-packet-routing srv6 locator\s+(\S+)\s+prefix\s+([\w:]+)\/([\d]+)/i);
      if (locM) {
        srv6Enabled = true;
        const name = locM[1];
        if (!locatorMap.has(name)) locatorMap.set(name, { name, prefix: locM[2], prefixLen: parseInt(locM[3]) });
        else { locatorMap.get(name).prefix = locM[2]; locatorMap.get(name).prefixLen = parseInt(locM[3]); }
        continue;
      }
      // ロケーター宣言のみ（prefix なし）
      const locDeclM = l.match(/^set routing-options source-packet-routing srv6 locator\s+(\S+)\s*$/i);
      if (locDeclM) {
        srv6Enabled = true;
        if (!locatorMap.has(locDeclM[1])) locatorMap.set(locDeclM[1], { name: locDeclM[1] });
        continue;
      }
      // ISIS で SRv6 利用
      if (/^set protocols isis source-packet-routing srv6\b/i.test(l)) {
        igpType = 'isis';
        continue;
      }
    }

    if (!srv6Enabled) return null;
    return { srv6Enabled, igpType, locators: [...locatorMap.values()] };
  }

  function showOspf(args, router, io) {
    const sub = _ex(args[0] || 'neighbor', ['neighbor','database']);
    if (sub === 'neighbor') {
      const neighbors = RouterOspf.getNeighbors(router.id);
      io.println('OSPF neighbor database:');
      io.println('Address         Interface      State           ID              Pri  Dead');
      if (neighbors.length === 0) io.println(' (no OSPF neighbors)');
      neighbors.forEach(n => {
        io.println(`${n.neighborIp.padEnd(16)}${(n.ifaceName||'-').padEnd(15)}Full            ${(n.neighborId||n.neighborIp).padEnd(16)}1    39`);
      });
    } else if (sub === 'database') {
      const db = RouterOspf.getDatabase();
      io.println('OSPF database, Area 0.0.0.0');
      io.println('Type       ID               Adv Rtr          Seq      Age  Opt  Cksum  Len');
      db.forEach(e => {
        io.println(`Router    *${(e.routerId||'-').padEnd(16)} ${(e.routerId||'-').padEnd(16)} 0x8000001  ${e.age||0}  0x22 0x${e.checksum||'0000'}  36`);
      });
    }
  }

  // ---- set コマンド処理 ----

  function _handleSet(parts, router, io) {
    // parts[0] = 'set', parts[1] = category, ...
    const cat = (parts[1] || '').toLowerCase();
    const rest = parts.slice(2);

    if (cat === 'system') {
      const key = (rest[0] || '').toLowerCase();
      if (key === 'host-name' && rest[1]) {
        _deleteLines(router, /^set system host-name\s+/i);
        _setLine(router, `set system host-name ${rest[1]}`);
        return true;
      }
    }

    if (cat === 'interfaces') {
      // set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
      const ifname = rest[0];
      if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
      const restStr = rest.slice(1).join(' ');
      const addrM = restStr.match(/unit\s+\d+\s+family\s+inet\s+address\s+([\d.]+\/[\d]+)/i);
      if (addrM) {
        // 同一 IF の既存 address 行を置換
        _deleteLines(router, new RegExp(`^set interfaces ${ifname.replace(/\//g,'\\/')} unit \\d+ family inet address `, 'i'));
        const line = `set interfaces ${ifname} ${restStr}`;
        _setLine(router, line);
        // GARP
        const ip = addrM[1].split('/')[0];
        _sendGarp(router, ifname, ip);
        return true;
      }
      // family inet6 address <addr>/<len>
      const addr6M = restStr.match(/unit\s+(\d+)\s+family\s+inet6\s+address\s+([\w:]+\/[\d]+)/i);
      if (addr6M) {
        const unit = addr6M[1];
        _deleteLines(router, new RegExp(`^set interfaces ${ifname.replace(/\//g,'\\/')} unit ${unit} family inet6 address `, 'i'));
        _setLine(router, `set interfaces ${ifname} ${restStr}`);
        return true;
      }
      // その他: そのまま保存
      _setLine(router, `set interfaces ${ifname} ${restStr}`);
      return true;
    }

    if (cat === 'routing-options') {
      const key = (rest[0] || '').toLowerCase();
      if (key === 'autonomous-system' && rest[1]) {
        _deleteLines(router, /^set routing-options autonomous-system\s+/i);
        _setLine(router, `set routing-options autonomous-system ${rest[1]}`);
        return true;
      }
      if (key === 'router-id' && rest[1]) {
        _deleteLines(router, /^set routing-options router-id\s+/i);
        _setLine(router, `set routing-options router-id ${rest[1]}`);
        return true;
      }
      // set routing-options static route <prefix/len> next-hop <nexthop> [preference <ad>]
      if (key === 'static' && (rest[1] || '').toLowerCase() === 'route') {
        const cidr = rest[2];
        if (!cidr || !cidr.includes('/')) { io.println('% Usage: set routing-options static route <prefix/len> next-hop <nexthop>'); return true; }
        const nhIdx = rest.findIndex(w => w.toLowerCase() === 'next-hop');
        if (nhIdx < 0 || !rest[nhIdx + 1]) { io.println('% next-hop required'); return true; }
        const nexthop = rest[nhIdx + 1];
        const prefIdx = rest.findIndex(w => w.toLowerCase() === 'preference');
        const ad = prefIdx >= 0 && rest[prefIdx + 1] ? ` preference ${rest[prefIdx + 1]}` : '';
        const cidrEsc = cidr.replace(/\./g,'\\.').replace(/:/g,'\\:').replace('/','\/');
        _deleteLines(router, new RegExp(`^set routing-options static route ${cidrEsc} next-hop\\s+`, 'i'));
        _setLine(router, `set routing-options static route ${cidr} next-hop ${nexthop}${ad}`);
        return true;
      }
      // set routing-options rib inet6.0 static route <prefix> next-hop <nexthop>
      if (key === 'rib' && (rest[1] || '').toLowerCase() === 'inet6.0') {
        if ((rest[2] || '').toLowerCase() === 'static' && (rest[3] || '').toLowerCase() === 'route') {
          const cidr6 = rest[4];
          if (!cidr6 || !cidr6.includes('/')) { io.println('% Usage: set routing-options rib inet6.0 static route <prefix/len> next-hop <nexthop>'); return true; }
          const nhIdx = rest.findIndex(w => w.toLowerCase() === 'next-hop');
          if (nhIdx < 0 || !rest[nhIdx + 1]) { io.println('% next-hop required'); return true; }
          const nexthop6 = rest[nhIdx + 1];
          const prefIdx = rest.findIndex(w => w.toLowerCase() === 'preference');
          const ad6 = prefIdx >= 0 && rest[prefIdx + 1] ? ` preference ${rest[prefIdx + 1]}` : '';
          const cidr6Esc = cidr6.replace(/:/g,'\\:').replace('/','\/');
          _deleteLines(router, new RegExp(`^set routing-options rib inet6\\.0 static route ${cidr6Esc} next-hop\\s+`, 'i'));
          _setLine(router, `set routing-options rib inet6.0 static route ${cidr6} next-hop ${nexthop6}${ad6}`);
          return true;
        }
      }
      // set routing-options source-packet-routing srv6 locator <NAME> [prefix <P/L>]
      if (key === 'source-packet-routing' && (rest[1] || '').toLowerCase() === 'srv6' && (rest[2] || '').toLowerCase() === 'locator' && rest[3]) {
        const locName = rest[3];
        if ((rest[4] || '').toLowerCase() === 'prefix' && rest[5] && rest[5].includes('/')) {
          _deleteLines(router, new RegExp(`^set routing-options source-packet-routing srv6 locator ${locName} prefix\\s+`, 'i'));
          _setLine(router, `set routing-options source-packet-routing srv6 locator ${locName} prefix ${rest[5]}`);
        } else {
          if (_setLineMissing(router, `set routing-options source-packet-routing srv6 locator ${locName}`)) {
            _setLine(router, `set routing-options source-packet-routing srv6 locator ${locName}`);
          }
        }
        if (window.RouterSrv6) window.RouterSrv6.recalculate();
        return true;
      }
    }

    if (cat === 'protocols') {
      const proto = (rest[0] || '').toLowerCase();
      if (proto === 'bgp') {
        const bgpRest = rest.slice(1);
        if ((bgpRest[0] || '').toLowerCase() === 'group') {
          const groupName = bgpRest[1];
          const groupRest = bgpRest.slice(2);
          const gKey = (groupRest[0] || '').toLowerCase();

          if (gKey === 'type') {
            _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} type\\s+`, 'i'));
            _setLine(router, `set protocols bgp group ${groupName} type ${groupRest[1] || 'external'}`);
            return true;
          }
          if (gKey === 'neighbor') {
            const nIp = groupRest[1];
            if (!nIp) { io.println('% Incomplete: neighbor IP required'); return true; }
            const nKey = (groupRest[2] || '').toLowerCase();
            if (nKey === 'peer-as') {
              const as = groupRest[3];
              if (!as) { io.println('% Incomplete: peer-as required'); return true; }
              _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} neighbor ${nIp.replace(/\./g,'\\.')} peer-as\\s+`, 'i'));
              _setLine(router, `set protocols bgp group ${groupName} neighbor ${nIp} peer-as ${as}`);
              // BGP セッション開始
              const procKey = `bgp group ${groupName}`;
              RouterBgp.teardownSession(router.id, nIp);
              RouterBgp.triggerSession(router, procKey, nIp, io);
              return true;
            }
            if (nKey === 'local-address') {
              const la = groupRest[3];
              _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} neighbor ${nIp.replace(/\./g,'\\.')} local-address\\s+`, 'i'));
              _setLine(router, `set protocols bgp group ${groupName} neighbor ${nIp} local-address ${la}`);
              return true;
            }
          }
        }
        // set protocols bgp network 10.0.0.0/24
        if ((bgpRest[0] || '').toLowerCase() === 'network') {
          const rawNet = bgpRest[1];
          if (!rawNet || !rawNet.includes('/')) { io.println('% Usage: set protocols bgp network <prefix>/<len>'); return true; }
          const [prefix, lenStr] = rawNet.split('/');
          const prefixLen = parseInt(lenStr, 10);
          if (_setLineMissing(router, `set protocols bgp network ${rawNet}`)) {
            _setLine(router, `set protocols bgp network ${rawNet}`);
          }
          RouterBgp.installRoutes(router.id, [{ prefix, prefixLen }], '0.0.0.0', [], 'self');
          RouterBgp.advertise(router, prefix, prefixLen, io);
          return true;
        }
      }
      if (proto === 'ospf') {
        const ospfRest = rest.slice(1);
        if ((ospfRest[0] || '').toLowerCase() === 'area') {
          const areaId = ospfRest[1];
          if (!areaId) { io.println('% Incomplete: area id required'); return true; }
          if ((ospfRest[2] || '').toLowerCase() === 'interface') {
            const ifname = ospfRest[3];
            if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
            const props = ospfRest.slice(4).join(' ');
            if (_setLineMissing(router, `set protocols ospf area ${areaId} interface ${ifname}`)) {
              _setLine(router, `set protocols ospf area ${areaId} interface ${ifname}`);
            }
            if (props) {
              _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')} interface ${ifname.replace(/\//g,'\\/')} (metric|passive)`, 'i'));
              _setLine(router, `set protocols ospf area ${areaId} interface ${ifname} ${props}`);
            }
            RouterOspf.recalculate(router.id);
            return true;
          }
        }
        return true;
      }
      if (proto === 'isis') {
        const isisRest = rest.slice(1);
        // source-packet-routing (SR) commands
        if ((isisRest[0] || '').toLowerCase() === 'source-packet-routing') {
          const sprest = isisRest.slice(1);
          if (sprest[0] === 'srgb' && sprest[1] === 'start-label' && sprest[2] && sprest[3] === 'index-range' && sprest[4]) {
            _deleteLines(router, /^set protocols isis source-packet-routing srgb/i);
            _setLine(router, `set protocols isis source-packet-routing srgb start-label ${sprest[2]} index-range ${sprest[4]}`);
            if (window.RouterSr) window.RouterSr.recalculate();
          } else if ((sprest[0] || '').toLowerCase() === 'srv6') {
            // set protocols isis source-packet-routing srv6 [locator <NAME>]
            if ((sprest[1] || '').toLowerCase() === 'locator' && sprest[2]) {
              _deleteLines(router, /^set protocols isis source-packet-routing srv6\b/i);
              _setLine(router, `set protocols isis source-packet-routing srv6 locator ${sprest[2]}`);
            } else {
              if (_setLineMissing(router, 'set protocols isis source-packet-routing srv6')) {
                _setLine(router, 'set protocols isis source-packet-routing srv6');
              }
            }
            if (window.RouterSrv6) window.RouterSrv6.recalculate();
          } else {
            _setLine(router, `set protocols isis source-packet-routing${sprest.length ? ' ' + sprest.join(' ') : ''}`);
            if (window.RouterSr) window.RouterSr.recalculate();
          }
          return true;
        }
        if ((isisRest[0] || '').toLowerCase() === 'interface') {
          const ifname = isisRest[1];
          if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
          // prefix-sid index N (SR)
          const irest = isisRest.slice(2);
          if (irest[0] === 'level' && irest[1] && irest[2] === 'prefix-sid' && irest[3] === 'index' && irest[4]) {
            _deleteLines(router, new RegExp(`^set protocols isis interface ${ifname.replace(/\./g,'\\.')} level ${irest[1]} prefix-sid`, 'i'));
            _setLine(router, `set protocols isis interface ${ifname} level ${irest[1]} prefix-sid index ${irest[4]}`);
            if (window.RouterSr) window.RouterSr.recalculate();
            return true;
          }
          const isisKey = isisRest.slice(2).join(' ');
          if (isisKey) {
            _deleteLines(router, new RegExp(`^set protocols isis interface ${ifname.replace(/\//g,'\\/')}\\s*$`, 'i'));
            _setLine(router, `set protocols isis interface ${ifname} ${isisKey}`);
          } else {
            if (_setLineMissing(router, `set protocols isis interface ${ifname}`)) {
              _setLine(router, `set protocols isis interface ${ifname}`);
            }
          }
          RouterIsis.recalculate(router.id);
          return true;
        }
        return true;
      }
      if (proto === 'mpls') {
        const mrest = rest.slice(1);
        if (mrest[0] === 'interface' && mrest[1]) {
          _setLine(router, `set protocols mpls interface ${mrest[1]}`);
          if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
          return true;
        }
        return true;
      }
      if (proto === 'ldp') {
        const lrest = rest.slice(1);
        if (lrest[0] === 'interface' && lrest[1]) {
          _setLine(router, `set protocols ldp interface ${lrest[1]}`);
          if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
          return true;
        }
        return true;
      }
    }

    if (cat === 'routing-instances') {
      const instName = rest[0];
      if (!instName) { io.println('% Incomplete: instance name required'); return true; }
      const restStr = rest.slice(1);
      const key = (restStr[0] || '').toLowerCase();
      if (key === 'instance-type') {
        _setLine(router, `set routing-instances ${instName} instance-type ${restStr[1] || 'vrf'}`);
        return true;
      }
      if (key === 'route-distinguisher' && restStr[1]) {
        _deleteLines(router, new RegExp(`^set routing-instances ${instName} route-distinguisher\\s+`, 'i'));
        _setLine(router, `set routing-instances ${instName} route-distinguisher ${restStr[1]}`);
        return true;
      }
      if (key === 'interface' && restStr[1]) {
        _setLine(router, `set routing-instances ${instName} interface ${restStr[1]}`);
        return true;
      }
      if (key === 'vrf-import' && restStr[1]) {
        _setLine(router, `set routing-instances ${instName} vrf-import ${restStr[1]}`);
        return true;
      }
      if (key === 'vrf-export' && restStr[1]) {
        _setLine(router, `set routing-instances ${instName} vrf-export ${restStr[1]}`);
        return true;
      }
      if (key === 'routing-options' && (restStr[1] || '').toLowerCase() === 'static' && (restStr[2] || '').toLowerCase() === 'route') {
        const cidr = restStr[3];
        if (!cidr || !cidr.includes('/')) { io.println('% Incomplete command.'); return true; }
        const nhIdx = restStr.findIndex(w => w.toLowerCase() === 'next-hop');
        if (nhIdx < 0 || !restStr[nhIdx + 1]) { io.println('% next-hop required'); return true; }
        const nexthop = restStr[nhIdx + 1];
        _deleteLines(router, new RegExp(`^set routing-instances ${instName} routing-options static route ${cidr.replace(/\./g,'\\.').replace('/','\/')} next-hop\\s+`, 'i'));
        _setLine(router, `set routing-instances ${instName} routing-options static route ${cidr} next-hop ${nexthop}`);
        return true;
      }
      io.println(`% Unknown routing-instances sub-command: ${restStr.join(' ')}`);
      return true;
    }

    if (cat === 'class-of-service') {
      return _handleSetCoS(parts, router, io);
    }

    if (cat === 'protocols' && (rest[0] || '').toLowerCase() === 'pim') {
      const pimRest = rest.slice(1);
      // set protocols pim interface <if> mode sparse
      if ((pimRest[0] || '').toLowerCase() === 'interface') {
        const ifname = pimRest[1];
        if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
        const props = pimRest.slice(2).join(' ');
        _deleteLines(router, new RegExp(`^set protocols pim interface ${ifname.replace(/\//g,'\\/')} `, 'i'));
        _setLine(router, `set protocols pim interface ${ifname}${props ? ' ' + props : ' mode sparse'}`);
        if (window.RouterMulticast) window.RouterMulticast.recalculate();
        return true;
      }
      // set protocols pim rp static address <ip> [group-ranges <prefix>/<len>]
      if ((pimRest[0] || '').toLowerCase() === 'rp' && (pimRest[1] || '').toLowerCase() === 'static' && (pimRest[2] || '').toLowerCase() === 'address') {
        const rpIp = pimRest[3];
        if (!rpIp) { io.println('% Incomplete: RP address required'); return true; }
        const grIdx = pimRest.findIndex(w => w.toLowerCase() === 'group-ranges');
        const grPrefix = grIdx >= 0 && pimRest[grIdx + 1] ? pimRest[grIdx + 1] : null;
        _deleteLines(router, new RegExp(`^set protocols pim rp static address ${rpIp.replace(/\./g,'\\.')}(\\s+.*)?$`, 'i'));
        const line = grPrefix
          ? `set protocols pim rp static address ${rpIp} group-ranges ${grPrefix}`
          : `set protocols pim rp static address ${rpIp}`;
        _setLine(router, line);
        if (window.RouterMulticast) window.RouterMulticast.recalculate();
        return true;
      }
      io.println(`% Unknown protocols pim sub-command`);
      return true;
    }

    io.println(`% Unknown set path: ${parts.slice(1).join(' ')}`);
    return true;
  }

  // ---- class-of-service set/delete ----

  function _handleSetCoS(parts, router, io) {
    // parts[0]='set', parts[1]='class-of-service', parts[2..]=rest
    const sub = (parts[2] || '').toLowerCase();
    const raw = parts.slice(2).join(' ');

    if (sub === 'classifiers') {
      // set class-of-service classifiers dscp <NAME> forwarding-class <FC> loss-priority <lp> code-points <cp>
      _deleteLines(router, new RegExp(`^set class-of-service classifiers dscp ${parts[3]} forwarding-class ${parts[5]} loss-priority \\S+ code-points \\S+`, 'i'));
      _setLine(router, `set class-of-service ${raw}`);
      return true;
    }
    if (sub === 'schedulers') {
      // set class-of-service schedulers <NAME> transmit-rate <rate>
      const name = parts[3];
      if (!name) { io.println('% Incomplete command.'); return true; }
      if ((parts[4] || '').toLowerCase() === 'transmit-rate' && parts[5]) {
        _deleteLines(router, new RegExp(`^set class-of-service schedulers ${name} transmit-rate\\s+`, 'i'));
        _setLine(router, `set class-of-service schedulers ${name} transmit-rate ${parts[5]}`);
      } else {
        _setLine(router, `set class-of-service ${raw}`);
      }
      return true;
    }
    if (sub === 'scheduler-maps') {
      _setLine(router, `set class-of-service ${raw}`);
      return true;
    }
    if (sub === 'interfaces') {
      const iface = parts[3];
      if (!iface) { io.println('% Incomplete command.'); return true; }
      if ((parts[4] || '').toLowerCase() === 'scheduler-map' && parts[5]) {
        _deleteLines(router, new RegExp(`^set class-of-service interfaces ${iface.replace(/\//g,'\\/')} scheduler-map\\s+`, 'i'));
        _setLine(router, `set class-of-service interfaces ${iface} scheduler-map ${parts[5]}`);
      } else {
        _setLine(router, `set class-of-service ${raw}`);
      }
      return true;
    }
    io.println(`% Unknown class-of-service sub-command: ${sub}`);
    return true;
  }

  function _handleDeleteCoS(parts, router, io) {
    // parts[0]='delete', parts[1]='class-of-service', parts[2..]=rest
    const sub = (parts[2] || '').toLowerCase();

    if (sub === 'classifiers') {
      const name = parts[4]; // dscp <NAME>
      if (name) {
        _deleteLines(router, new RegExp(`^set class-of-service classifiers dscp ${name}\\s+`, 'i'));
      } else {
        _deleteLines(router, /^set class-of-service classifiers\s+/i);
      }
      return true;
    }
    if (sub === 'schedulers') {
      const name = parts[3];
      if (name) {
        _deleteLines(router, new RegExp(`^set class-of-service schedulers ${name}\\s+`, 'i'));
      } else {
        _deleteLines(router, /^set class-of-service schedulers\s+/i);
      }
      return true;
    }
    if (sub === 'scheduler-maps') {
      const name = parts[3];
      if (name) {
        _deleteLines(router, new RegExp(`^set class-of-service scheduler-maps ${name}\\s+`, 'i'));
      } else {
        _deleteLines(router, /^set class-of-service scheduler-maps\s+/i);
      }
      return true;
    }
    if (sub === 'interfaces') {
      const iface = parts[3];
      if (iface) {
        _deleteLines(router, new RegExp(`^set class-of-service interfaces ${iface.replace(/\//g,'\\/')}\\s+`, 'i'));
      } else {
        _deleteLines(router, /^set class-of-service interfaces\s+/i);
      }
      return true;
    }
    _deleteLines(router, /^set class-of-service\s+/i);
    return true;
  }

  function _setLineMissing(router, line) {
    const cfg = Storage.read(router.id, 'running') || '';
    return !cfg.split('\n').some(l => l.trim() === line.trim());
  }

  // ---- delete コマンド処理 ----

  function _handleDelete(parts, router, io) {
    const cat = (parts[1] || '').toLowerCase();
    const rest = parts.slice(2);

    if (cat === 'interfaces') {
      const ifname = rest[0];
      if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
      _deleteLines(router, new RegExp(`^set interfaces ${ifname.replace(/\//g,'\\/')}\\s+`, 'i'));
      return true;
    }

    if (cat === 'protocols') {
      const proto = (rest[0] || '').toLowerCase();
      if (proto === 'bgp') {
        const bgpRest = rest.slice(1);
        if ((bgpRest[0]||'').toLowerCase() === 'group') {
          const groupName = bgpRest[1];
          const groupRest = bgpRest.slice(2);
          if ((groupRest[0]||'').toLowerCase() === 'neighbor') {
            const nIp = groupRest[1];
            _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} neighbor ${nIp.replace(/\./g,'\\.')}\\s+`, 'i'));
            RouterBgp.teardownSession(router.id, nIp);
            return true;
          }
          // delete entire group
          _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName}\\s+`, 'i'));
          return true;
        }
        if ((bgpRest[0]||'').toLowerCase() === 'network') {
          const rawNet = bgpRest[1];
          if (!rawNet) { io.println('% Incomplete'); return true; }
          const [prefix, lenStr] = rawNet.split('/');
          const prefixLen = parseInt(lenStr || '0', 10);
          _deleteLines(router, new RegExp(`^set protocols bgp network ${rawNet.replace(/\//g,'\\/')}$`, 'i'));
          RouterBgp.withdraw(router, prefix, prefixLen);
          return true;
        }
      }
      if (proto === 'ospf') {
        const ospfRest = rest.slice(1);
        if ((ospfRest[0] || '').toLowerCase() === 'area') {
          const areaId = ospfRest[1];
          if (!areaId) {
            // delete all OSPF config
            _deleteLines(router, /^set protocols ospf\s+/i);
          } else if ((ospfRest[2] || '').toLowerCase() === 'interface') {
            if (ospfRest[3]) {
              const ifname = ospfRest[3];
              _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')} interface ${ifname.replace(/\//g,'\\/')}(\\s+.*)?$`, 'i'));
            } else {
              _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')} interface\\s+`, 'i'));
            }
          } else {
            _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')}\\s+`, 'i'));
          }
        } else {
          _deleteLines(router, /^set protocols ospf\s+/i);
        }
        RouterOspf.recalculate(router.id);
        return true;
      }
      if (proto === 'isis') {
        const isisRest = rest.slice(1);
        // delete protocols isis source-packet-routing
        if ((isisRest[0] || '').toLowerCase() === 'source-packet-routing') {
          if (isisRest[1] === 'srgb') {
            _deleteLines(router, /^set protocols isis source-packet-routing srgb\s+/i);
            if (window.RouterSr) window.RouterSr.recalculate();
          } else if (isisRest[1] === 'srv6') {
            if ((isisRest[2] || '').toLowerCase() === 'locator' && isisRest[3]) {
              _deleteLines(router, new RegExp(`^set protocols isis source-packet-routing srv6 locator ${isisRest[3]}\\b`, 'i'));
            } else {
              _deleteLines(router, /^set protocols isis source-packet-routing srv6\b/i);
            }
            if (window.RouterSrv6) window.RouterSrv6.recalculate();
          } else {
            _deleteLines(router, /^set protocols isis source-packet-routing/i);
            if (window.RouterSr) window.RouterSr.recalculate();
            if (window.RouterSrv6) window.RouterSrv6.recalculate();
          }
          return true;
        }
        if ((isisRest[0] || '').toLowerCase() === 'interface') {
          if (isisRest[1]) {
            const ifname = isisRest[1];
            // delete protocols isis interface <name> level <L> prefix-sid
            const irest = isisRest.slice(2);
            if (irest[0] === 'level' && irest[1] && irest[2] === 'prefix-sid') {
              _deleteLines(router, new RegExp(`^set protocols isis interface ${ifname.replace(/\./g,'\\.')} level ${irest[1]} prefix-sid`, 'i'));
              if (window.RouterSr) window.RouterSr.recalculate();
              return true;
            }
            _deleteLines(router, new RegExp(`^set protocols isis interface ${ifname.replace(/\//g,'\\/')}(\\s+.*)?$`, 'i'));
          } else {
            _deleteLines(router, /^set protocols isis interface\s+/i);
          }
        } else {
          _deleteLines(router, /^set protocols isis\s+/i);
        }
        RouterIsis.recalculate(router.id);
        return true;
      }
      if (proto === 'pim') {
        const pimRest = rest.slice(1);
        if ((pimRest[0] || '').toLowerCase() === 'interface' && pimRest[1]) {
          _deleteLines(router, new RegExp(`^set protocols pim interface ${pimRest[1].replace(/\//g,'\\/')}(\\s+.*)?$`, 'i'));
        } else if ((pimRest[0] || '').toLowerCase() === 'rp') {
          _deleteLines(router, /^set protocols pim rp\s+/i);
        } else {
          _deleteLines(router, /^set protocols pim\s+/i);
        }
        if (window.RouterMulticast) window.RouterMulticast.recalculate();
        return true;
      }
      if (proto === 'mpls') {
        if (rest[1] === 'interface' && rest[2]) {
          _deleteLines(router, new RegExp(`^set protocols mpls interface ${rest[2].replace(/\//g,'\\/')}$`, 'i'));
        } else {
          _deleteLines(router, /^set protocols mpls\s+/i);
        }
        if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
        return true;
      }
      if (proto === 'ldp') {
        if (rest[1] === 'interface' && rest[2]) {
          _deleteLines(router, new RegExp(`^set protocols ldp interface ${rest[2].replace(/\//g,'\\/')}$`, 'i'));
        } else {
          _deleteLines(router, /^set protocols ldp\s+/i);
        }
        if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
        return true;
      }
    }

    if (cat === 'routing-options') {
      const key = (rest[0] || '').toLowerCase();
      if (key === 'autonomous-system') { _deleteLines(router, /^set routing-options autonomous-system\s+/i); return true; }
      if (key === 'router-id') { _deleteLines(router, /^set routing-options router-id\s+/i); return true; }
      if (key === 'static' && (rest[1] || '').toLowerCase() === 'route' && rest[2]) {
        const cidr = rest[2];
        _deleteLines(router, new RegExp(`^set routing-options static route ${cidr.replace(/\./g,'\\.').replace('/','\/')}\\s+`, 'i'));
        return true;
      }
      if (key === 'rib' && (rest[1] || '').toLowerCase() === 'inet6.0' && (rest[2] || '').toLowerCase() === 'static' && (rest[3] || '').toLowerCase() === 'route' && rest[4]) {
        const cidr6 = rest[4];
        const cidr6Esc = cidr6.replace(/:/g,'\\:').replace('/','\/');
        _deleteLines(router, new RegExp(`^set routing-options rib inet6\\.0 static route ${cidr6Esc}\\s+`, 'i'));
        return true;
      }
      // delete routing-options source-packet-routing srv6 [locator <NAME>]
      if (key === 'source-packet-routing' && (rest[1] || '').toLowerCase() === 'srv6') {
        if ((rest[2] || '').toLowerCase() === 'locator' && rest[3]) {
          _deleteLines(router, new RegExp(`^set routing-options source-packet-routing srv6 locator ${rest[3]}`, 'i'));
        } else {
          _deleteLines(router, /^set routing-options source-packet-routing srv6\b/i);
        }
        if (window.RouterSrv6) window.RouterSrv6.recalculate();
        return true;
      }
    }

    if (cat === 'routing-instances') {
      const instName = rest[0];
      if (!instName) { io.println('% Incomplete: instance name required'); return true; }
      if (rest[1]) {
        const key = (rest[1] || '').toLowerCase();
        if (key === 'interface' && rest[2]) {
          _deleteLines(router, new RegExp(`^set routing-instances ${instName} interface ${rest[2].replace(/\//g,'\\/')}$`, 'i'));
          return true;
        }
        if (key === 'route-distinguisher') {
          _deleteLines(router, new RegExp(`^set routing-instances ${instName} route-distinguisher\\s+`, 'i'));
          return true;
        }
        if (key === 'routing-options' && rest[2] && rest[3] && rest[4]) {
          const cidr = rest[4];
          _deleteLines(router, new RegExp(`^set routing-instances ${instName} routing-options static route ${cidr.replace(/\./g,'\\.').replace('/','\/')}\\s+`, 'i'));
          return true;
        }
      }
      _deleteLines(router, new RegExp(`^set routing-instances ${instName}(\\s+.*)?$`, 'i'));
      return true;
    }

    if (cat === 'class-of-service') {
      return _handleDeleteCoS(parts, router, io);
    }

    io.println(`% Unknown delete path: ${parts.slice(1).join(' ')}`);
    return true;
  }

  // ---- メインコマンドハンドラ ----

  // モード別動詞候補
  const _ECANDS_J = ['commit','edit','exit','ping','request','set','show','write'];
  const _ECFG_J   = ['commit','delete','exit','quit','rename','rollback','set','show','top'];

  function handleCommand(parts, state, io) {
    const router = state.router;
    const _vcands = state.configMode === 'edit' ? _ECFG_J : _ECANDS_J;
    const verb = _ex(parts[0], _vcands);

    // ---- 設定モード（edit 後）----
    if (state.configMode === 'edit') {
      if (verb === 'exit' || verb === 'quit') {
        state.configMode = null;
        io.println('Exiting configuration mode');
        return true;
      }
      if (verb === 'top') { return true; } // already at top

      if (verb === 'show') {
        const _SHOW_J = ['interfaces','bgp','route','configuration','running-config','version','arp','isis','ospf','routing-instances','ldp','spring-te'];
        const sub = _ex(parts[1], _SHOW_J);
        if (!sub || sub === '|' || sub === 'all') { showConfig(router, io); return true; }
        // show interfaces etc. from config mode
      }

      if (verb === 'commit') {
        Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
        io.println('commit complete');
        return true;
      }

      if (verb === 'rollback') {
        // rollback 0: discard uncommitted changes (restore from startup)
        const startup = Storage.read(router.id, 'startup') || '';
        Storage.write(router.id, 'running', startup);
        io.println('load complete');
        return true;
      }

      if (verb === 'set') {
        return _handleSet(parts, router, io);
      }

      if (verb === 'delete') {
        return _handleDelete(parts, router, io);
      }

      if (verb === 'rename') { io.println('% rename not supported in emulation'); return true; }

      io.println(`% Unknown configuration command: ${parts.join(' ')}`);
      return true;
    }

    // ---- オペレーショナルモード ----

    if (verb === 'edit') {
      io.println('Entering configuration mode');
      io.println('{master:0}[edit]');
      state.configMode = 'edit';
      return true;
    }

    if (verb === 'set' && !state.configMode) {
      // set from operational mode → delegate to config handler
      const saved = state.configMode;
      state.configMode = 'edit';
      _handleSet(parts, router, io);
      state.configMode = saved;
      return true;
    }

    if (verb === 'show') {
      const _SHOW_J = ['class-of-service','interfaces','bgp','route','configuration','running-config','version','arp','isis','ospf','routing-instances','ldp','spring-te','ipv6','srv6','pim'];
      const sub = _ex(parts[1], _SHOW_J);

      if (sub === 'pim') {
        const sub2 = (parts[2] || 'neighbors').toLowerCase();
        if (sub2 === 'neighbors' || sub2 === 'neighbor') {
          const neighbors = window.RouterMulticast ? window.RouterMulticast.getPimNeighbors(router.id) : [];
          io.println('');
          io.println('Instance: master');
          io.println('');
          if (neighbors.length === 0) {
            io.println(' (no PIM neighbors)');
          } else {
            io.println('Neighbor address  Interface              Status      Uptime   DR pri');
            for (const n of neighbors) {
              const sec = Math.floor((Date.now() - n.establishedAt) / 1000);
              const h = Math.floor(sec/3600), m = Math.floor((sec%3600)/60), s = sec%60;
              const uptime = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
              io.println(`${(n.neighborIp||n.neighborId).padEnd(18)}${n.localIface.padEnd(23)}Up           ${uptime}  1`);
            }
          }
          return true;
        }
        if (sub2 === 'rps' || sub2 === 'rp') {
          const rpMappings = window.RouterMulticast ? window.RouterMulticast.getRpMappings(router.id) : [];
          io.println('');
          io.println('Instance: master');
          io.println('');
          if (rpMappings.length === 0) {
            io.println(' (no RP mappings)');
          } else {
            io.println('RP address       Type   Holdtime Timeout Groups Group prefixes');
            for (const m of rpMappings) {
              io.println(`${m.rpIp.padEnd(17)}static 0        -       0      ${m.groupPrefix}/${m.groupPrefixLen}`);
            }
          }
          return true;
        }
        if (sub2 === 'join') {
          const mrib = window.RouterMulticast ? window.RouterMulticast.getMrib(router.id) : [];
          io.println('');
          io.println('Instance: master');
          io.println('');
          if (mrib.length === 0) {
            io.println(' (no PIM join entries)');
          } else {
            for (const entry of mrib) {
              io.println(`Group: ${entry.group}`);
              io.println(`    Source: *`);
              io.println(`    RP: ${entry.rp}`);
              io.println(`    Flags: sparse,rptree,wildcard`);
              io.println(`    Upstream interface: ${entry.iif || 'Null'}`);
              entry.oifList.forEach(oif => io.println(`    Downstream interface list: ${oif}`));
              io.println('');
            }
          }
          return true;
        }
        io.println(`% Unknown 'show pim ${sub2}'`);
        return true;
      }

      // show class-of-service interface [<ifname>] | show class-of-service classifier name [<name>]
      if (sub === 'class-of-service') {
        const cfg = Storage.read(router.id, 'running') || '';
        const cosCfg = RouterQos.parseJunosCoS(cfg);
        const sub2 = (parts[2] || '').toLowerCase();
        if (sub2 === 'interface' || sub2 === '') {
          const target = parts[3];
          const grouped = new Map();
          cosCfg.ifaceSchedulerMaps.forEach(e => {
            if (target && !e.iface.toLowerCase().startsWith(target.toLowerCase())) return;
            if (!grouped.has(e.iface)) grouped.set(e.iface, []);
            grouped.get(e.iface).push(e.mapName);
          });
          if (grouped.size === 0) { io.println('  (no class-of-service interface config)'); return true; }
          for (const [iface, maps] of grouped) {
            io.println(`Physical interface: ${iface}`);
            maps.forEach(mapName => {
              const mapEntries = cosCfg.schedulerMaps.filter(m => m.mapName === mapName);
              if (mapEntries.length === 0) {
                io.println(`  Scheduler map: ${mapName}`);
              } else {
                mapEntries.forEach(me => {
                  const sched = cosCfg.schedulers.find(s => s.name === me.schedulerName);
                  io.println(`  Scheduler map: ${mapName}, Scheduler: ${me.schedulerName}`);
                  if (sched) io.println(`    Transmit rate: ${sched.transmitRate}`);
                });
              }
            });
          }
          return true;
        }
        if (sub2 === 'classifier') {
          const target = parts[4]; // classifier name [<name>]
          let shown = 0;
          const byName = new Map();
          cosCfg.classifiers.forEach(c => {
            if (target && c.name.toLowerCase() !== target.toLowerCase()) return;
            if (!byName.has(c.name)) byName.set(c.name, []);
            byName.get(c.name).push(c);
          });
          for (const [name, entries] of byName) {
            io.println(`Classifier: ${name}`);
            entries.forEach(e => io.println(`  Forwarding class: ${e.fc}  Code point: ${e.codePoint}`));
            shown++;
          }
          if (shown === 0) io.println('  (no classifiers configured)');
          return true;
        }
        io.println(`% Unknown: show class-of-service ${sub2}`);
        return true;
      }

      // show srv6
      if (sub === 'srv6') {
        if (!window.RouterSrv6) { io.println('% SRv6 not initialized'); return true; }
        const sub2 = _ex(parts[2] || 'locator', ['locator', 'sid', 'state']);
        if (sub2 === 'locator') {
          const locs = window.RouterSrv6.getLocators(router.id);
          if (locs.length === 0) { io.println('  (SRv6 not configured)'); return true; }
          io.println('Locator Name     Prefix                    SID Count');
          for (const loc of locs) {
            const sids = window.RouterSrv6.getSidDb(router.id).filter(e => e.locatorName === loc.name);
            const pfx = loc.prefix ? `${loc.prefix}/${loc.prefixLen}` : '-';
            io.println(`${loc.name.padEnd(17)}${pfx.padEnd(26)}${sids.length}`);
          }
          return true;
        }
        if (sub2 === 'sid') {
          const sids = window.RouterSrv6.getSidDb(router.id);
          io.println('SID                    Behavior  Locator    State');
          if (sids.length === 0) { io.println('  (none)'); return true; }
          for (const s of sids) {
            io.println(`${s.sid.padEnd(23)}${s.behavior.padEnd(10)}${s.locatorName.padEnd(11)}${s.valid ? 'Active' : 'Invalid'}`);
          }
          return true;
        }
        if (sub2 === 'state') {
          const srv6State = window.RouterSrv6.getSrv6State(router.id);
          io.println(`SRv6 Enabled: ${srv6State.srv6Enabled ? 'Yes' : 'No'}`);
          io.println('Encapsulation source address: ::');
          return true;
        }
        io.println(`% Unknown: show srv6 ${parts[2] || ''}`);
        return true;
      }

      // show route table srv6.inet6.3
      if (sub === 'route' && (parts[2] || '').toLowerCase() === 'table' && (parts[3] || '').toLowerCase() === 'srv6.inet6.3') {
        if (!window.RouterSrv6) { io.println('% SRv6 not initialized'); return true; }
        const entries = window.RouterSrv6.getFwdTable(router.id);
        io.println(`srv6.inet6.3: ${entries.length} destinations, ${entries.length} routes (${entries.length} active, 0 holddown, 0 hidden)`);
        io.println('+ = Active Route, - = Last Active, * = Both');
        io.println('');
        for (const e of entries) {
          const prefix = `${e.locatorPrefix}/${e.prefixLen}`;
          io.println(`${prefix.toUpperCase().padEnd(20)}  *[SRv6/9] 00:01:00`);
          io.println(`                     > to ${e.nexthopIp.toUpperCase()} via ${e.iface}`);
        }
        if (entries.length === 0) io.println('  (no SRv6 forwarding entries)');
        return true;
      }

      if (sub === 'ipv6') {
        if (!window.RouterIpv6) { io.println('% IPv6 not initialized'); return true; }
        const Ipv6 = window.RouterIpv6;
        const sub2 = (parts[2] || '').toLowerCase();
        if (sub2 === 'neighbor' || sub2 === 'neighbors') {
          const neighbors = Ipv6.getNdpNeighbors(router.id);
          io.println('IPv6 Neighbor Cache:');
          io.println('IPv6 Address                            State Expires    Interface');
          neighbors.forEach(n => {
            io.println(n.addr.toUpperCase().padEnd(40) + n.state.padEnd(6) + ' -         ' + n.iface);
          });
          if (neighbors.length === 0) io.println(' (no NDP neighbors)');
          return true;
        }
        io.println(`% Unknown: show ipv6 ${parts[2] || ''}`); return true;
      }
      // show route table inet6.0
      if (sub === 'route') {
        if ((parts[2] || '').toLowerCase() === 'table' && (parts[3] || '').toLowerCase() === 'inet6.0') {
          if (!window.RouterIpv6) { io.println('% IPv6 not initialized'); return true; }
          const routes = window.RouterIpv6.getIpv6Routes(router.id);
          io.println(`inet6.0: ${routes.length} destinations, ${routes.length} routes (${routes.length} active, 0 holddown, 0 hidden)`);
          io.println('');
          io.println('+ = Active Route, - = Last Active, * = Both');
          io.println('');
          routes.forEach(r => {
            if (r.type === 'C') {
              io.println(`${r.prefix.toUpperCase()}/${r.prefixLen}     *[Direct/0] preference 0`);
              io.println(`                    > via ${r.iface}`);
            } else if (r.type === 'L') {
              io.println(`${r.prefix.toUpperCase()}/${r.prefixLen}       *[Local/0] preference 0`);
              io.println(`                      Local via ${r.iface}`);
            } else if (r.type === 'S') {
              io.println(`${r.prefix.toUpperCase()}/${r.prefixLen}   *[Static/${r.ad}] preference ${r.ad}`);
              io.println(`                    > to ${r.nexthop.toUpperCase()}`);
            }
          });
          if (routes.length === 0) io.println('  (no IPv6 routes)');
          return true;
        }
      }
      if (sub === 'interfaces' || sub === 'interface') {
        showInterfaces(parts.slice(2), router, io); return true;
      }
      if (sub === 'bgp') {
        showBgp(parts.slice(2), router, io); return true;
      }
      if (sub === 'route') {
        if ((parts[2] || '').toLowerCase() === 'table' && parts[3]) {
          const tableName = parts[3];
          if (tableName.toLowerCase() === 'mpls.0') {
            if (!window.RouterMpls) { io.println('% MPLS not initialized'); return true; }
            const table = window.RouterMpls.getForwardingTable(router.id);
            const count = table.length;
            io.println(`mpls.0: ${count} destinations, ${count} routes (${count} active, 0 holddown, 0 hidden)`);
            io.println('');
            io.println('+ = Active Route, - = Last Active, * = Both');
            io.println('');
            if (table.length === 0) { io.println('(no MPLS forwarding entries)'); return true; }
            table.forEach(e => {
              io.println(`${e.inLabel}                 *[LDP/9] 00:01:00, metric 1`);
              const actionStr = e.action === 'pop' ? 'Pop' : `Swap ${e.outLabel}`;
              io.println(`                    > to ${e.nexthop} via ${e.iface}, ${actionStr}`);
            });
            return true;
          }
          if (tableName.toLowerCase() === 'inet.3') {
            if (!window.RouterSr) { io.println('% Segment Routing not initialized'); return true; }
            const entries = window.RouterSr.getSrLfib(router.id);
            const count = entries.length;
            io.println(`inet.3: ${count} destinations, ${count} routes (${count} active, 0 holddown, 0 hidden)`);
            io.println('');
            io.println('+ = Active Route, - = Last Active, * = Both');
            io.println('');
            if (entries.length === 0) { io.println('(no SR forwarding entries)'); return true; }
            entries.forEach(e => {
              const actionStr = e.action === 'pop' ? 'Pop' : `Swap ${e.outLabel}`;
              io.println(`${e.prefix}  *[SPRING-TE/9] 00:01:00`);
              io.println(`                > to ${e.nexthop} via ${e.iface}, ${actionStr}`);
            });
            return true;
          }
          const instName = tableName.replace(/\.inet\.0$/i, '');
          if (instName !== tableName) {
            const cfg = Storage.read(router.id, 'running') || '';
            const insts = getRoutingInstances(cfg);
            const inst = insts.find(i => i.name === instName);
            if (!inst) { io.println(`% Routing table ${tableName} not found`); return true; }
            const instCands = [];
            const re2 = new RegExp(`^set routing-instances ${instName} routing-options static route ([\\d.]+\\/\\d+) next-hop ([\\d.]+)(?:\\s+preference\\s+(\\d+))?`, 'gim');
            let m2;
            while ((m2 = re2.exec(cfg))) {
              const [pfx, lenStr] = m2[1].split('/');
              instCands.push({ type: 'Static', prefix: pfx, prefixLen: parseInt(lenStr), ad: m2[3] ? parseInt(m2[3]) : 1, nexthop: m2[2] });
            }
            const allIfaces = getInterfaces(cfg);
            inst.ifaces.forEach(ifName => {
              const f = allIfaces.find(x => x.name === ifName);
              if (!f) return;
              const netOcts = f.ip.split('.').map(Number);
              const maskOcts = f.mask.split('.').map(Number);
              const net = netOcts.map((b, i) => b & maskOcts[i]).join('.');
              instCands.push({ type: 'Direct', prefix: net, prefixLen: f.prefixLen, ad: 0, metric: 0, via: f.name });
              instCands.push({ type: 'Local',  prefix: f.ip, prefixLen: 32,          ad: 0, metric: 0, via: f.name });
            });
            io.println('');
            io.println(`${tableName}: routes`);
            io.println('');
            if (instCands.length === 0) { io.println(`% No routes in table ${tableName}`); return true; }
            RouterRib.selectBest(instCands).forEach(r => {
              if (r.type === 'Direct') {
                io.println(`${r.prefix}/${r.prefixLen}            *[Direct/0] preference 0`);
                io.println(`                    > via ${r.via}`);
              } else if (r.type === 'Local') {
                io.println(`${r.prefix}/${r.prefixLen}              *[Local/0] preference 0`);
                io.println(`                      Local via ${r.via}`);
              } else if (r.type === 'Static') {
                io.println(`${r.prefix}/${r.prefixLen}       *[Static/${r.ad}] preference ${r.ad}`);
                io.println(`                    > to ${r.nexthop}`);
              }
            });
            return true;
          }
        }
        showRoute(parts.slice(2), router, io); return true;
      }
      if (sub === 'ldp') {
        if (!window.RouterMpls) { io.println('% MPLS not initialized'); return true; }
        const sub2 = _ex(parts[2] || 'neighbor', ['neighbor', 'database']);
        if (sub2 === 'neighbor') {
          const neighbors = window.RouterMpls.getNeighbors(router.id);
          io.println('Address          Interface              State     ID               Hold time  KA hold time');
          if (neighbors.length === 0) io.println(' (no LDP neighbors)');
          neighbors.forEach(n => {
            io.println(`${n.neighborIp.padEnd(17)}${n.iface.padEnd(23)}Operational  ${n.ldpId.padEnd(17)}15         30`);
          });
          return true;
        }
        if (sub2 === 'database') {
          const cfg = Storage.read(router.id, 'running') || '';
          const neighbors = window.RouterMpls.getNeighbors(router.id);
          const bindings = window.RouterMpls.getBindings(router.id);
          const myLdp = getBgpRouterId(cfg);
          neighbors.forEach(n => {
            io.println(`Input label database, ${myLdp}:0--${n.ldpId}`);
            io.println('  Label     Prefix');
            bindings.forEach(b => {
              const r = b.remoteBindings.find(rb => rb.lsr === n.ldpId);
              if (r) io.println(`  ${r.label.padEnd(10)}${b.fec}`);
            });
            io.println('');
            io.println(`Output label database, ${myLdp}:0--${n.ldpId}`);
            io.println('  Label     Prefix');
            bindings.forEach(b => {
              io.println(`  ${b.localLabel.padEnd(10)}${b.fec}`);
            });
            io.println('');
          });
          return true;
        }
        io.println(`% Unknown 'show ldp ${parts[2]}'`);
        return true;
      }
      if (sub === 'configuration') {
        showConfig(router, io); return true;
      }
      if (sub === 'running-config') {
        showConfig(router, io); return true;
      }
      if (sub === 'version') {
        const host = getHostname(Storage.read(router.id, 'running') || '') || router.hostname || router.id;
        io.println('Junos OS Release 22.4R1 (emulated)');
        io.println(`Model: vmx`);
        io.println(`Hostname: ${host}`);
        return true;
      }
      if (sub === 'arp') {
        const cfg = Storage.read(router.id, 'running') || '';
        const rIdx = topoIdx(router.id);
        const ifaces = getInterfaces(cfg);
        io.println('MAC Address       Address         Name                      Interface               Flags');
        ifaces.forEach((f, idx) => {
          if (/^lo/i.test(f.name)) return;
          const mac = Packets ? Packets.buildIfaceMac(rIdx, idx) : null;
          const macStr = mac ? Array.from(mac).map(b => b.toString(16).padStart(2,'0')).join(':') : '??:??:??:??:??:??';
          io.println(`${macStr.padEnd(18)}${f.ip.padEnd(16)}${f.ip.padEnd(26)}${f.name.padEnd(24)}none`);
        });
        if (global.RouterSender && global.RouterSender.getArpEntries) {
          global.RouterSender.getArpEntries(router.id).forEach(e => {
            const macHex = Array.from(e.mac).map(b => b.toString(16).padStart(2,'0')).join(':');
            io.println(`${macHex.padEnd(18)}${e.ip.padEnd(16)}${e.ip.padEnd(26)}${(e.iface||'-').padEnd(24)}none`);
          });
        }
        return true;
      }
      if (sub === 'isis') {
        const sub2 = _ex(parts[2] || 'adjacency', ['adjacency','database','spring-adjacencies']);
        if (sub2 === 'spring-adjacencies') {
          if (!window.RouterSr) { io.println('% Segment Routing not initialized'); return true; }
          const entries = window.RouterSr.getSrLfib(router.id);
          io.println('SPRING Adjacency Database:');
          io.println('Interface         Neighbor          Label');
          entries.forEach(e => {
            io.println(`${(e.iface||'-').padEnd(18)}${e.nexthop.padEnd(18)}${e.inLabel}`);
          });
          if (entries.length === 0) io.println(' (none)');
          return true;
        }
        if (sub2 === 'adjacency') {
          const adjs = RouterIsis.getAdjacencies(router.id);
          io.println('IS-IS adjacency database:');
          io.println('Interface       L  State         Hold (secs)');
          if (adjs.length === 0) io.println(' (no IS-IS adjacencies)');
          adjs.forEach(a => {
            io.println(`${a.ifaceName.padEnd(16)}${a.level}  ${a.state.padEnd(14)}${29}`);
          });
        } else if (sub2 === 'database') {
          const db = RouterIsis.getDatabase();
          io.println('IS-IS level 2 link-state database:');
          io.println('');
          db.forEach(e => {
            io.println(`${e.lspId}  Sequence: ${e.seq}  Checksum: ${e.checksum}  Lifetime: ${e.lifetime}`);
            io.println('  IS neighbor: (links in this domain)');
          });
        }
        return true;
      }
      if (sub === 'ospf') {
        showOspf(parts.slice(2), router, io); return true;
      }
      if (sub === 'routing-instances') {
        const cfg = Storage.read(router.id, 'running') || '';
        const insts = getRoutingInstances(cfg);
        io.println('Instance               Type            RD                    Ifaces');
        insts.forEach(inst => {
          io.println(inst.name.padEnd(23) + 'vrf'.padEnd(16) + (inst.rd || 'not set').padEnd(22) + inst.ifaces.join(', '));
        });
        if (insts.length === 0) io.println('(no routing instances configured)');
        return true;
      }
      // show spring-te label-range
      if (sub === 'spring-te') {
        if (!window.RouterSr) { io.println('% Segment Routing not initialized'); return true; }
        const blk = window.RouterSr.getSrLabelBlock(router.id);
        io.println(`Label range: ${blk.base} - ${blk.end}`);
        return true;
      }
      io.println(`% Unknown show command: ${sub}`);
      return true;
    }

    if (verb === 'request') {
      // request system halt/reboot etc. — no-op in emulation
      io.println('% request not supported in emulation');
      return true;
    }

    if (verb === 'ping') {
      // ping ipv6 <addr>
      if ((parts[1] || '').toLowerCase() === 'ipv6') {
        const addr = parts[2];
        if (!addr) { io.println('% Usage: ping ipv6 <addr>'); return true; }
        if (!window.RouterIpv6) { io.println('% IPv6 not initialized'); return true; }
        const neighbors = window.RouterIpv6.getNdpNeighbors(router.id);
        const target = window.RouterIpv6.canonIpv6(addr);
        const reachable = neighbors.some(n => n.addr === target);
        io.println(`PING6 ${addr}: 56 data bytes`);
        for (let i = 1; i <= 5; i++) {
          if (reachable) io.println(`64 bytes from ${addr}: icmp_seq=${i} ttl=64 time=1.0 ms`);
          else io.println(`Request timeout for icmp_seq ${i}`);
        }
        io.println(`--- ${addr} ping statistics ---`);
        io.println(`5 packets transmitted, ${reachable ? 5 : 0} received, ${reachable ? 0 : 100}% packet loss`);
        return true;
      }
      // existing ping (IPv4)
      io.println('% ping not fully supported in emulation'); return true;
    }

    if (verb === 'commit') {
      Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
      io.println('commit complete');
      return true;
    }

    if (verb === 'write' || verb === 'wr') {
      io.println("unknown command: write");
      io.println("Use 'edit' then 'commit' to save configuration.");
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
      const cfg = Storage.read(router.id, 'running') || '';
      return getInterfaces(cfg).map(f => f.name);
    }

    if (state && state.configMode === 'edit') {
      if (before.length === 0) {
        return ['set','delete','show','commit','rollback','exit','top'].filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if (v === 'set' && before.length === 1) {
        return ['system','interfaces','routing-options','protocols'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'interfaces' && before.length === 2) {
        return ifaceNames().filter(n => n.startsWith(last));
      }
      if (v === 'set' && before[1] === 'interfaces' && before.length >= 3) {
        if (before.length === 3) return ['unit'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[3] === 'unit' && before.length === 4) return ['0'].filter(s => s.startsWith(last));
        if (before.length === 5) return ['family'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[5] === 'family' && before.length === 6) return ['inet'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[6] === 'inet' && before.length === 7) return ['address'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'routing-options' && before.length === 2) {
        return ['autonomous-system','router-id'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'protocols' && before.length === 2) {
        return ['bgp','isis','ldp','mpls','ospf'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'protocols' && before[2] === 'bgp' && before.length === 3) {
        return ['group','network'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'protocols' && before[2] === 'bgp' && before[3] === 'group') {
        if (before.length === 4) return []; // group name
        if (before.length === 5) return ['type','neighbor'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[5] === 'neighbor' && before.length === 6) return []; // IP
        if (before[5] === 'neighbor' && before.length === 7) return ['peer-as','local-address'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'delete' && before.length === 1) {
        return ['interfaces','routing-options','protocols'].filter(s => s.startsWith(last.toLowerCase()));
      }
      return [];
    }

    // operational mode
    if (before.length === 0) {
      return ['show','edit','set','commit','ping','clear','help'].filter(c => c.startsWith(last.toLowerCase()));
    }
    const verb = before[0];
    if (verb === 'show' && before.length === 1) {
      return ['interfaces','bgp','ldp','route','configuration','version','arp','isis','ospf'].filter(s => s.startsWith(last.toLowerCase()));
    }
    if (verb === 'show' && before[1] === 'bgp' && before.length === 2) {
      return ['summary'].filter(s => s.startsWith(last.toLowerCase()));
    }
    if (verb === 'show' && before[1] === 'ospf' && before.length === 2) {
      return ['neighbor','database'].filter(s => s.startsWith(last.toLowerCase()));
    }
    return [];
  }

  // ---- BGP セッション復元 ----

  function restoreBgpSessions(router) {
    RouterBgp.restoreSessions(router);
  }

  // ---- JunOS config パーサ（RouterBgp 登録用）----

  const _junosParser = {
    getBgpAs,
    getBgpRouterId,
    getBgpNetworks,
    hasBgpNeighbor(cfg, peerIp) {
      return getBgpNeighbors(cfg).some(n => n.ip === peerIp);
    },
    getNeighborUpdateSource(cfg, neighborIp) {
      const n = getBgpNeighbors(cfg).find(n => n.ip === neighborIp);
      if (!n || !n.localAddress) return null;
      // local-address は IP なので、その IP を持つ interface 名を返す
      const iface = getInterfaces(cfg).find(f => f.ip === n.localAddress);
      return iface ? iface.name : null;
    },
    getInterfaceList(cfg) {
      return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
    },
    getNeighbors(cfg) {
      return getBgpNeighbors(cfg).map(n => ({
        neighborIp: n.ip,
        procKey: `bgp group ${n.groupName}`,
      }));
    },
  };

  RouterBgp.registerOsParser('junos', _junosParser);

  // IS-IS パーサ登録
  RouterIsis.registerOsParser('junos', {
    getIsisConfig(cfg) {
      const lines = (cfg || '').split('\n');
      const hasIsisIf = lines.some(l => /^set protocols isis interface\s+\S+/i.test(l));
      if (!hasIsisIf) return null;

      const ridM = (cfg || '').match(/^set routing-options router-id\s+([\d.]+)/im);
      const ifaceList = getInterfaces(cfg);
      const lo0 = ifaceList.find(f => /^lo/i.test(f.name));
      const sysIp = ridM ? ridM[1] : (lo0 ? lo0.ip : null);
      let net = null;
      if (sysIp) {
        const octets = sysIp.split('.').map(n => parseInt(n, 10).toString(16).padStart(2, '0'));
        net = `49.0001.0000.${octets[0]}${octets[1]}.${octets[2]}${octets[3]}.00`;
      }
      if (!net) return null;

      const interfaces = [];
      for (const l of lines) {
        const m = l.match(/^set protocols isis interface\s+(\S+)(?:\s+metric\s+(\d+))?(?:\s+(passive))?/i);
        if (!m) continue;
        const name = m[1];
        if (name.toLowerCase() === 'all') continue;
        const existing = interfaces.find(i => i.name === name);
        if (existing) {
          if (m[2]) existing.metric = parseInt(m[2]);
          if (m[3]) existing.passive = true;
        } else {
          interfaces.push({ name, metric: m[2] ? parseInt(m[2]) : 10, passive: !!m[3] });
        }
      }

      return { process: 'isis', net, isType: 'level-2-only', interfaces };
    },
    getInterfaceList(cfg) {
      return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
    },
  });

  // OSPF パーサ登録
  RouterOspf.registerOsParser('junos', {
    getOspfConfig(cfg) {
      const ospf = getOspfConfig(cfg);
      if (!ospf) return null;
      const areas = {};
      for (const [areaId, ifArr] of Object.entries(ospf.areas)) {
        const ifaces = ifArr.map(ifObj => {
          const metM = (ifObj.props || '').match(/metric\s+(\d+)/i);
          const passive = /passive/i.test(ifObj.props || '');
          return { name: ifObj.name, cost: metM ? parseInt(metM[1]) : 1, passive };
        });
        areas[areaId] = { interfaces: ifaces };
      }
      return { process: 'ospf', routerId: null, areas };
    },
    getInterfaceList(cfg) {
      return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
    },
  });

  // MPLS パーサ登録
  if (window.RouterMpls) {
    window.RouterMpls.registerOsParser('junos', {
      getMplsConfig,
      getInterfaceList(cfg) {
        return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
      },
    });
  }

  // SR パーサ登録
  if (window.RouterSr) {
    window.RouterSr.registerOsParser('junos', {
      getSrConfig,
      getInterfaceList(cfg) {
        return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
      },
    });
  }

  // SRv6 パーサ登録
  if (window.RouterSrv6) {
    window.RouterSrv6.registerOsParser('junos', {
      getSrv6Config,
      getInterfaceList(cfg) {
        return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
      },
    });
  }

  // Multicast パーサ登録
  if (window.RouterMulticast) {
    window.RouterMulticast.registerOsParser('junos', {
      getMulticastConfig(cfg) {
        const ifaceLines = (cfg || '').match(/^set protocols pim interface (\S+)/gim) || [];
        const interfaces = ifaceLines.map(l => {
          const m = l.match(/^set protocols pim interface (\S+)/i);
          return m ? { name: m[1], mode: 'sparse' } : null;
        }).filter(Boolean);
        const enabled = interfaces.length > 0 || /^set protocols pim rp\s+/im.test(cfg);
        const rpMappings = [];
        const rpRe = /^set protocols pim rp static address ([\d.]+)(?:\s+group-ranges\s+([\d.]+\/[\d]+))?/gim;
        let m;
        while ((m = rpRe.exec(cfg || ''))) {
          const rpIp = m[1];
          const gr = m[2] ? m[2].split('/') : ['224.0.0.0', '4'];
          rpMappings.push({ rpIp, groupPrefix: gr[0], groupPrefixLen: parseInt(gr[1], 10) });
        }
        return { enabled, interfaces, rpMappings };
      },
      getInterfaceList(cfg) {
        return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
      },
    });
  }

  global.RouterJunos = { handleCommand, complete, restoreBgpSessions };

  // restoreAll に SRv6 / Multicast を追加
  setTimeout(() => { if (window.RouterSrv6) window.RouterSrv6.restoreAll(); if (window.RouterMulticast) window.RouterMulticast.restoreAll(); }, 0);

  // IPv6 パーサ登録
  if (window.RouterIpv6) {
    window.RouterIpv6.registerOsParser('junos', {
      getInterfaceAddrs(cfg) {
        const result = [];
        const re4 = /^set interfaces (\S+) unit (\d+) family inet address ([\d.]+)\/([\d]+)/gim;
        const re6 = /^set interfaces (\S+) unit (\d+) family inet6 address ([\w:]+)\/([\d]+)/gim;
        const map = new Map();
        let m;
        while ((m = re4.exec(cfg || ''))) {
          const key = `${m[1]}.${m[2]}`;
          if (!map.has(key)) map.set(key, { name: key, ipv4: [], ipv6: [], shutdown: false });
          map.get(key).ipv4.push({ ip: m[3], prefixLen: parseInt(m[4], 10) });
        }
        while ((m = re6.exec(cfg || ''))) {
          const key = `${m[1]}.${m[2]}`;
          if (!map.has(key)) map.set(key, { name: key, ipv4: [], ipv6: [], shutdown: false });
          map.get(key).ipv6.push({ addr: m[3], prefixLen: parseInt(m[4], 10), type: 'global' });
        }
        return [...map.values()];
      },
      getIpv6StaticRoutes(cfg) {
        const result = [];
        const re = /^set routing-options rib inet6\.0 static route ([\w:]+)\/([\d]+) next-hop ([\w:]+)(?:\s+preference\s+(\d+))?/gim;
        let m;
        while ((m = re.exec(cfg || ''))) {
          result.push({ prefix: m[1], prefixLen: parseInt(m[2], 10), nexthop: m[3], ad: m[4] ? parseInt(m[4], 10) : 1 });
        }
        return result;
      },
    });
  }
})(window);

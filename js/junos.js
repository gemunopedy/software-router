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

  function getBgpAs(cfg) {
    const m = (cfg || '').match(/^set routing-options autonomous-system\s+(\d+)/im);
    return m ? parseInt(m[1], 10) : 65000;
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
    if (!Packets || !global.RouterCapture) return;
    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = getInterfaces(cfg);
    const idx = ifaces.findIndex(f => f.name === ifaceName);
    const ifaceIdx = idx >= 0 ? idx : 0;
    const mac = Packets.buildIfaceMac(topoIdx(router.id), ifaceIdx);
    const pkt = Packets.buildPacket({ proto: 'arp', op: 1, src: addr, dst: addr, srcMac: mac });
    global.RouterCapture.emit(router.id, pkt, { iface: ifaceName });
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
    ifaces.forEach(f => {
      const netOcts = f.ip.split('.').map(Number);
      const maskOcts = f.mask.split('.').map(Number);
      const net = netOcts.map((b, i) => b & maskOcts[i]).join('.');
      io.println(`${net}/${f.prefixLen}            *[Direct/0] preference 0`);
      io.println(`                    > via ${f.name}`);
      io.println(`${f.ip}/32              *[Local/0] preference 0`);
      io.println(`                      Local via ${f.name}`);
    });
    const bgpRoutes = RouterBgp.getRib(router.id).filter(e => e.selected && e.neighborIp !== 'self');
    bgpRoutes.forEach(e => {
      io.println(`${e.prefix}/${e.prefixLen}     *[BGP/${e.asPath.join(' ')}]`);
      io.println(`                    > to ${e.nextHop}`);
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
    const roM = cfg.match(/^set routing-options/gim);
    if (roM) {
      io.println('routing-options {');
      if (asn) io.println(`    autonomous-system ${asn};`);
      if (rid) io.println(`    router-id ${rid};`);
      io.println('}');
    }
    const neighbors = getBgpNeighbors(cfg);
    const networks  = getBgpNetworks(cfg);
    if (neighbors.length || networks.length) {
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
      io.println('    }');
      io.println('}');
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
    }

    io.println(`% Unknown set path: ${parts.slice(1).join(' ')}`);
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
    }

    if (cat === 'routing-options') {
      const key = (rest[0] || '').toLowerCase();
      if (key === 'autonomous-system') { _deleteLines(router, /^set routing-options autonomous-system\s+/i); return true; }
      if (key === 'router-id') { _deleteLines(router, /^set routing-options router-id\s+/i); return true; }
    }

    io.println(`% Unknown delete path: ${parts.slice(1).join(' ')}`);
    return true;
  }

  // ---- メインコマンドハンドラ ----

  function handleCommand(parts, state, io) {
    const router = state.router;
    const verb = (parts[0] || '').toLowerCase();

    // ---- 設定モード（edit 後）----
    if (state.configMode === 'edit') {
      if (verb === 'exit' || verb === 'quit') {
        state.configMode = null;
        io.println('Exiting configuration mode');
        return true;
      }
      if (verb === 'top') { return true; } // already at top

      if (verb === 'show') {
        const sub = (parts[1] || '').toLowerCase();
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
      const sub = (parts[1] || '').toLowerCase();
      if (sub === 'interfaces' || sub === 'interface') {
        showInterfaces(parts.slice(2), router, io); return true;
      }
      if (sub === 'bgp') {
        showBgp(parts.slice(2), router, io); return true;
      }
      if (sub === 'route') {
        showRoute(parts.slice(2), router, io); return true;
      }
      if (sub === 'configuration') {
        showConfig(router, io); return true;
      }
      if (sub === 'running-config') {
        // support for cross-OS show running-config
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
      io.println(`% Unknown show command: ${sub}`);
      return true;
    }

    if (verb === 'request') {
      // request system halt/reboot etc. — no-op in emulation
      io.println('% request not supported in emulation');
      return true;
    }

    if (verb === 'commit') {
      // commit from operational mode (some JunOS allows this)
      Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
      io.println('commit complete');
      return true;
    }

    if (verb === 'write' || verb === 'wr') {
      io.println('unknown command: write');
      io.println('Use "edit" then "commit" to save configuration.');
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
        return ['bgp'].filter(s => s.startsWith(last.toLowerCase()));
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
      return ['interfaces','bgp','route','configuration','version','arp'].filter(s => s.startsWith(last.toLowerCase()));
    }
    if (verb === 'show' && before[1] === 'bgp' && before.length === 2) {
      return ['summary'].filter(s => s.startsWith(last.toLowerCase()));
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

  global.RouterJunos = { handleCommand, complete, restoreBgpSessions };
})(window);

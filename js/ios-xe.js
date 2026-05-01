// IOS-XE CLI エミュレーション。
// commands.js から os === 'ios-xe' のときに呼ばれる。
//
// 公開:
//   RouterIosXe.handleCommand(parts, state, io)
//     parts: コマンドトークン配列（先頭が動詞）
//     戻り値: true=handled / false=unknown
(function (global) {
  const Storage = global.RouterStorage;
  const Packets = global.RouterPackets;
  const Capture = global.RouterCapture;

  // --------- パーサユーティリティ ---------

  function readCfg(router) {
    return Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
  }

  // config から interface ブロックを [{name, attrs:[{key,val}]}] で返す
  function parseInterfaces(cfg) {
    const blocks = [];
    let cur = null;
    for (const raw of cfg.split('\n')) {
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

  // interface ブロックから ip address を取得 ("A.B.C.D M.M.M.M" 形式を返す)
  function getIfIp(iface) {
    for (const l of iface.lines) {
      const m = l.match(/^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (m) return { ip: m[1], mask: m[2] };
    }
    return null;
  }

  // shutdown 状態か判定（shutdown あり かつ no shutdown なし）
  function isIfShutdown(iface) {
    let down = false;
    for (const l of iface.lines) {
      if (/^shutdown$/i.test(l)) down = true;
      else if (/^no\s+shutdown$/i.test(l)) down = false;
    }
    return down;
  }

  // IOS-XE 省略名 → 正式名へ展開 (例: Gi1 → GigabitEthernet1)
  const IF_EXPAND = [
    [/^Gi(\d)/i,   'GigabitEthernet'],
    [/^Te(\d)/i,   'TenGigabitEthernet'],
    [/^Fa(\d)/i,   'FastEthernet'],
    [/^Lo(\d)/i,   'Loopback'],
    [/^Po(\d)/i,   'Port-channel'],
    [/^Tu(\d)/i,   'Tunnel'],
    [/^Vl(\d)/i,   'Vlan'],
    [/^Ma(\d)/i,   'Management'],
  ];
  function expandIfName(name) {
    for (const [re, full] of IF_EXPAND) {
      if (re.test(name)) return name.replace(re, (_, n) => full + n);
    }
    return name;
  }

  // subnet mask → /prefix
  function maskToPrefix(mask) {
    return mask.split('.').reduce((n, o) => n + (parseInt(o, 10).toString(2).match(/1/g) || []).length, 0);
  }

  // 行中の hostname を取得
  function getHostname(cfg) {
    const m = cfg.match(/^hostname\s+(\S+)/im);
    return m ? m[1] : null;
  }

  // --------- ユーティリティ ---------

  // トポロジー上の 1-based インスタンス ID を返す
  function topoIdx(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // GARP (Gratuitous ARP Request) を capture に emit する
  // op=1 (request): sender IP = target IP = addr, target MAC = 00:00:00:00:00:00, dst eth = broadcast
  function _sendGarp(router, ifaceName, addr) {
    if (!Packets || !Capture) return;
    const cfg = readCfg(router);
    // interface の宣言順から 0-based ifaceIdx を求める
    let ifaceIdx = 0, counter = 0;
    for (const line of cfg.split('\n')) {
      const m = line.match(/^interface\s+(\S+)/i);
      if (!m) continue;
      if (m[1].toLowerCase() === ifaceName.toLowerCase()) { ifaceIdx = counter; break; }
      counter++;
    }
    const mac = Packets.buildIfaceMac(topoIdx(router.id), ifaceIdx);
    const pkt = Packets.buildPacket({
      proto: 'arp', op: 1,
      src: addr, dst: addr,
      srcMac: mac,
    });
    Capture.emit(router.id, pkt, { iface: ifaceName });
  }

  // IF 単位の MAC を Cisco ドット表記で返す (例: 5000.0001.0000)
  // routerIdx: 1-based instance ID, ifaceIdx: 0-based interface 順
  function ifaceMacStr(routerIdx, ifaceIdx) {
    const b = global.RouterPackets.buildIfaceMac(routerIdx, ifaceIdx);
    const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 4)}.${h.slice(4, 8)}.${h.slice(8, 12)}`;
  }

  // --------- show サブコマンド ---------

  const showHandlers = {};

  // show running-config [interface <name>] [| section <pattern>]
  showHandlers['running-config'] = showHandlers['run'] = (args, router, io) => {
    const cfg = readCfg(router);

    // フィルタ: | section <pattern>
    const sectionIdx = args.indexOf('|');
    if (sectionIdx >= 0) {
      const op = args[sectionIdx + 1];
      if (op === 'section' || op === 'include' || op === 'exclude') {
        const pat = args.slice(sectionIdx + 2).join(' ');
        filterOutput(cfg, op, pat, io);
        return;
      }
    }

    // interface 絞り込み: show running-config interface Gi0/0
    const ifIdx = args.findIndex(a => /^interface$/i.test(a));
    if (ifIdx >= 0) {
      const targetIf = args[ifIdx + 1];
      if (!targetIf) { io.println('% Incomplete command'); return; }
      const blocks = parseInterfaces(cfg);
      // 前方一致で検索（Gi → GigabitEthernet）
      const block = blocks.find(b => b.name.toLowerCase().startsWith(targetIf.toLowerCase()) ||
                                     targetIf.toLowerCase().startsWith(b.name.toLowerCase().slice(0,3)));
      if (!block) {
        io.println(`% Invalid interface: ${targetIf}`);
        return;
      }
      io.println('Building configuration...');
      io.println('');
      io.println(`interface ${block.name}`);
      block.lines.forEach(l => io.println(' ' + l));
      io.println('end');
      io.println('');
      return;
    }

    // full output
    printRunningConfig(cfg, router, io);
  };

  // show startup-config
  showHandlers['startup-config'] = showHandlers['start'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'startup') || '';
    io.println('Using 1024 out of 262144 bytes');
    io.println('!');
    io.println('! Last configuration change by console');
    io.println('!');
    (cfg || '[empty]').split('\n').forEach(l => io.println(l));
    io.println('end');
  };

  // show version
  showHandlers['version'] = showHandlers['ver'] = (args, router, io) => {
    const host = getHostname(readCfg(router)) || router.hostname || router.id;
    io.println('Cisco IOS XE Software, Version 17.15.1 (emulated)');
    io.println('Technical Support: http://www.cisco.com/techsupport');
    io.println('');
    io.println(`ROM: IOS-XE ROMMON`);
    io.println('');
    io.println(`${host} uptime is 0 minutes`);
    io.println('');
    io.println('cisco CSR1000v (VXE) processor (revision V00) with 2097143K/6147K bytes of memory.');
    io.println('1 Gigabit Ethernet interface');
    io.println('32768K bytes of non-volatile configuration memory.');
    io.println('');
    io.println('License Level: ax');
    io.println('License Type: Default. No valid license found.');
    io.println('');
    io.println('Configuration register is 0x2102');
  };

  // show ip interface brief
  showHandlers['ip'] = (args, router, io) => {
    const sub = args[0] ? args[0].toLowerCase() : '';
    const cfg = readCfg(router);

    if (sub === 'interface' && (args[1] || '').match(/^br/i)) {
      // show ip interface brief
      io.println('Interface              IP-Address      OK? Method Status                Protocol');
      parseInterfaces(cfg).forEach(iface => {
        const ipInfo = getIfIp(iface);
        const ip = ipInfo ? ipInfo.ip : 'unassigned';
        const ok = ipInfo ? 'YES' : 'NO ';
        io.println(
          iface.name.padEnd(22) +
          ip.padEnd(16) +
          ok + ' manual ' +
          'up'.padEnd(22) + 'up'
        );
      });
      return;
    }

    if (sub === 'interface') {
      // show ip interface [<name>]
      const targetIf = args[1];
      const blocks = parseInterfaces(cfg);
      const list = targetIf
        ? blocks.filter(b => b.name.toLowerCase().startsWith(targetIf.toLowerCase()))
        : blocks;
      list.forEach(iface => {
        const ipInfo = getIfIp(iface);
        io.println(`${iface.name} is up, line protocol is up`);
        if (ipInfo) {
          io.println(`  Internet address is ${ipInfo.ip}/${maskToPrefix(ipInfo.mask)}`);
          io.println(`  Broadcast address is 255.255.255.255`);
          io.println(`  MTU is 1500 bytes`);
        } else {
          io.println('  Internet protocol processing disabled');
        }
      });
      return;
    }

    if (sub === 'route') {
      // show ip route (簡易)
      io.println('Codes: C - connected, S - static, R - RIP, M - mobile, B - BGP');
      io.println('       D - EIGRP, EX - EIGRP external, O - OSPF, ...');
      io.println('');
      io.println('Gateway of last resort is not set');
      io.println('');
      parseInterfaces(cfg).forEach(iface => {
        const ipInfo = getIfIp(iface);
        if (!ipInfo) return;
        const prefix = maskToPrefix(ipInfo.mask);
        // ネットワークアドレスを計算
        const ipParts = ipInfo.ip.split('.').map(Number);
        const maskParts = ipInfo.mask.split('.').map(Number);
        const net = ipParts.map((b, i) => b & maskParts[i]).join('.');
        io.println(`C     ${net}/${prefix} is directly connected, ${iface.name}`);
        io.println(`L     ${ipInfo.ip}/32 is directly connected, ${iface.name}`);
      });
      const bgpRoutes = (_bgpRib.get(router.id) || []).filter(e => e.selected && e.neighborIp !== 'self');
      bgpRoutes.forEach(e => {
        io.println(`B     ${e.prefix}/${e.prefixLen} [20/0] via ${e.nextHop}, 00:00:00`);
      });
      return;
    }

    if (sub === 'bgp') {
      showIpBgp(args.slice(1), router, cfg, io);
      return;
    }

    io.println(`% Invalid input detected after 'show ip ${sub}'`);
  };

  // show arp
  showHandlers['arp'] = (args, router, io) => {
    const cfg = readCfg(router);
    const selfIfaces = parseInterfaces(cfg);
    const rIdx = topoIdx(router.id);

    io.println('Protocol  Address          Age (min)  Hardware Addr   Type   Interface');

    // 自インタフェースのエントリ（age = -）: IF インデックスごとに異なる MAC
    // Loopback は物理 IF ではないので除外
    selfIfaces.forEach((iface, ifaceIdx) => {
      if (/^loopback/i.test(iface.name)) return;
      if (isIfShutdown(iface)) return;
      const ipInfo = getIfIp(iface);
      if (!ipInfo) return;
      io.println(
        'Internet  ' + ipInfo.ip.padEnd(17) + '-          ' +
        ifaceMacStr(rIdx, ifaceIdx).padEnd(16) + 'ARPA   ' + expandIfName(iface.name)
      );
    });

    // ダイナミックエントリ（ARP 解決済みキャッシュ）
    if (global.RouterSender && global.RouterSender.getArpEntries) {
      global.RouterSender.getArpEntries(router.id).forEach(e => {
        const macHex = Array.from(e.mac).map(b => b.toString(16).padStart(2,'0')).join('');
        const macDot = macHex.slice(0,4) + '.' + macHex.slice(4,8) + '.' + macHex.slice(8,12);
        const age = Math.floor((Date.now() - e.ts) / 60000);
        const iface = e.iface ? expandIfName(e.iface) : '-';
        io.println('Internet  ' + e.ip.padEnd(17) + String(age).padEnd(11) + macDot.padEnd(16) + 'ARPA   ' + iface);
      });
    }
  };

  // show interfaces [<name>] [counters]
  showHandlers['interfaces'] = showHandlers['interface'] = (args, router, io) => {
    const cfg = readCfg(router);
    const targetIf = args[0] && !/^(brief|counters|status)$/i.test(args[0]) ? args[0] : null;
    const brief = args.some(a => /^brief$/i.test(a));

    if (brief) {
      io.println('Interface              Status         Protocol  Description');
      parseInterfaces(cfg).forEach(iface => {
        const desc = iface.lines.find(l => /^description/i.test(l));
        io.println(
          iface.name.padEnd(22) +
          'up'.padEnd(15) +
          'up'.padEnd(10) +
          (desc ? desc.replace(/^description\s*/i, '') : '')
        );
      });
      return;
    }

    const blocks = parseInterfaces(cfg);
    const list = targetIf
      ? blocks.filter(b => b.name.toLowerCase().startsWith(targetIf.toLowerCase()))
      : blocks;

    if (list.length === 0) { io.println(`% Invalid interface: ${targetIf}`); return; }

    list.forEach(iface => {
      const ipInfo = getIfIp(iface);
      io.println(`${iface.name} is up, line protocol is up`);
      io.println(`  Hardware is CSR vNIC, address is aabb.cc00.0100`);
      if (ipInfo) io.println(`  Internet address is ${ipInfo.ip}/${maskToPrefix(ipInfo.mask)}`);
      io.println(`  MTU 1500 bytes, BW 1000000 Kbit/sec`);
      io.println(`  Input queue: 0/375/0/0 (size/max/drops/flushes)`);
      io.println(`  5 minute input rate 0 bits/sec, 0 packets/sec`);
      io.println(`  5 minute output rate 0 bits/sec, 0 packets/sec`);
      io.println('');
    });
  };

  // show ospf (簡易プレースホルダ)
  showHandlers['ospf'] = (args, router, io) => {
    io.println(' Routing Process "ospf 1" with ID 0.0.0.0');
    io.println(' Start time: 00:00:00.000, Time elapsed: 00:00:00.000');
    io.println(' Supports only single TOS(TOS0) routes');
    io.println(' (emulated - no real OSPF process running)');
  };

  // show clock
  showHandlers['clock'] = (args, router, io) => {
    const now = new Date();
    io.println(`${now.toTimeString().slice(0,8)}.${String(now.getMilliseconds()).padStart(3,'0')} ` +
               `UTC ${now.toDateString()}`);
  };

  // show history
  showHandlers['history'] = (args, router, io) => {
    io.println('% Command history is available via the ↑ / ↓ arrow keys in this terminal.');
  };

  // ------- フィルタ (| include / exclude / section) -------
  function filterOutput(cfg, op, pat, io) {
    let re;
    try { re = new RegExp(pat, 'i'); } catch (_) { re = new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'); }
    const lines = cfg.split('\n');

    if (op === 'include') {
      lines.filter(l => re.test(l)).forEach(l => io.println(l));
      return;
    }
    if (op === 'exclude') {
      lines.filter(l => !re.test(l)).forEach(l => io.println(l));
      return;
    }
    if (op === 'section') {
      let printing = false;
      for (const line of lines) {
        const isHeader = /^[^\s!]/.test(line);
        if (re.test(line)) { printing = true; }
        else if (isHeader && printing) { printing = false; }
        if (printing) io.println(line);
      }
    }
  }

  // ------- config 編集ヘルパー -------

  // 指定インタフェースブロック内の行を更新/追加する
  function _updateIfaceLine(router, ifaceName, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n');
    let inBlock = false, replaced = false;
    const out = [];
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) {
        inBlock = im[1].toLowerCase() === ifaceName.toLowerCase();
        out.push(t); continue;
      }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; }
        else if (t.startsWith(' ') || t.startsWith('\t')) {
          if (matchRe.test(t.trim())) { out.push(' ' + newLine); replaced = true; continue; }
        }
      }
      out.push(t);
    }
    // 行が見つからなかった場合は該当ブロック末尾に追加
    if (!replaced) {
      const insertIdx = out.findIndex((l, idx) =>
        /^interface\s+/i.test(out[idx]) &&
        out[idx].match(/^interface\s+(\S+)/i)[1].toLowerCase() === ifaceName.toLowerCase()
      );
      if (insertIdx >= 0) {
        let end = insertIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t') || out[end] === '')) end++;
        out.splice(end, 0, ' ' + newLine);
      }
    }
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // 指定インタフェースブロック内のマッチ行を削除する
  function _removeIfaceLine(router, ifaceName, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { inBlock = im[1].toLowerCase() === ifaceName.toLowerCase(); return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) {
        return !matchRe.test(t.trim());
      }
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // インタフェースブロックを丸ごと削除する
  function _removeIface(router, ifaceName) {
    const cfg = Storage.read(router.id, 'running') || '';
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) {
        skip = im[1].toLowerCase() === ifaceName.toLowerCase() ||
               im[1].toLowerCase().startsWith(ifaceName.toLowerCase());
        return !skip;
      }
      if (skip) {
        if ((t.startsWith(' ') || t.startsWith('\t') || t === '')) return false;
        skip = false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // ---- router プロセスブロック用 helpers ----

  // BGP TCP リトライタイマー: 'routerId:neighborIp' -> timerId
  const _bgpRetryTimers = new Map();
  // BGP セッション確立済みフラグ: 'routerId:neighborIp' -> true
  const _bgpEstablished = new Map();
  // BGP セッション情報: 'routerId:neighborIp' -> { establishedAt: ms, keepaliveTimer: timerId }
  const _bgpSessionInfo = new Map();
  // BGP RIB: 'routerId' -> [{prefix, prefixLen, nextHop, asPath, origin, neighborIp, selected}]
  const _bgpRib = new Map();

  // リトライをスケジュール（共通ヘルパー）
  function _scheduleRetry(timerKey, router, procKey, neighborIp, io) {
    if (_bgpRetryTimers.has(timerKey)) clearTimeout(_bgpRetryTimers.get(timerKey));
    const tid = setTimeout(() => {
      _bgpRetryTimers.delete(timerKey);
      try { _triggerBgpTcp(router, procKey, neighborIp, io); } catch (_) {}
    }, 10000);
    _bgpRetryTimers.set(timerKey, tid);
  }

  // config から BGP AS 番号を取得
  function _getBgpAs(cfg) {
    const m = cfg.match(/^router\s+bgp\s+(\d+)/im);
    return m ? parseInt(m[1], 10) : 65000;
  }

  // config から BGP Router-ID を取得（bgp router-id > Loopback0 IP > 最初の IF IP）
  function _getBgpRouterId(cfg) {
    const ridM = cfg.match(/^\s*bgp\s+router-id\s+([\d.]+)/im);
    if (ridM) return ridM[1];
    const ifaces = parseInterfaces(cfg);
    const lo = ifaces.find(b => /^loopback0$/i.test(b.name));
    if (lo) { const ip = getIfaceIp(lo); if (ip) return ip; }
    for (const b of ifaces) { const ip = getIfaceIp(b); if (ip) return ip; }
    return '0.0.0.0';
  }

  // クラスフルデフォルトマスク
  function _classfulMask(ip) {
    const first = parseInt((ip || '0').split('.')[0], 10);
    if (first < 128) return '255.0.0.0';
    if (first < 192) return '255.255.0.0';
    return '255.255.255.0';
  }

  // router bgp ブロックから network 文を収集
  function _getBgpNetworks(cfg) {
    const lines = (cfg || '').split('\n');
    const hi = lines.findIndex(l => /^router\s+bgp\s+\d+\s*$/i.test(l.trimEnd()));
    if (hi < 0) return [];
    const result = [];
    for (let i = hi + 1; i < lines.length; i++) {
      const l = lines[i];
      if (l !== '' && !/^[ \t]/.test(l)) break;
      const m = l.trim().match(/^network\s+([\d.]+)(?:\s+mask\s+([\d.]+))?$/i);
      if (!m) continue;
      const prefix = m[1], mask = m[2] || _classfulMask(m[1]);
      result.push({ prefix, mask, prefixLen: maskToPrefix(mask) });
    }
    return result;
  }

  // BGP RIB にルートを upsert 登録（neighborIp='self' のとき自局 originate）
  function _installBgpRoutes(routerId, routes, nextHop, asPath, neighborIp) {
    if (!_bgpRib.has(routerId)) _bgpRib.set(routerId, []);
    const rib = _bgpRib.get(routerId);
    const src = neighborIp || nextHop;
    for (const r of routes) {
      const key = `${r.prefix}/${r.prefixLen}`;
      const idx = rib.findIndex(e => `${e.prefix}/${e.prefixLen}` === key && e.neighborIp === src);
      const entry = { prefix: r.prefix, prefixLen: r.prefixLen, nextHop, asPath: [...asPath], origin: 'i', neighborIp: src, selected: true };
      if (idx >= 0) rib[idx] = entry;
      else rib.push(entry);
    }
  }

  // 指定ネイバーから学習したルートを RIB から全削除
  function _clearBgpRoutesFromNeighbor(routerId, neighborIp) {
    if (!_bgpRib.has(routerId)) return;
    _bgpRib.set(routerId, _bgpRib.get(routerId).filter(e => e.neighborIp !== neighborIp));
  }

  // 指定ネイバーから学習した特定ルートのみ RIB から削除
  function _withdrawRoutesFromNeighbor(routerId, routes, neighborIp) {
    if (!_bgpRib.has(routerId)) return;
    const keys = new Set(routes.map(r => `${r.prefix}/${r.prefixLen}`));
    _bgpRib.set(routerId, _bgpRib.get(routerId).filter(e => !(keys.has(`${e.prefix}/${e.prefixLen}`) && e.neighborIp === neighborIp)));
  }

  // BGP セッションを完全に切断し RIB も清掃する
  function _teardownBgpSession(routerId, neighborIp) {
    const tk = routerId + ':' + neighborIp;
    if (_bgpRetryTimers.has(tk)) { clearTimeout(_bgpRetryTimers.get(tk)); _bgpRetryTimers.delete(tk); }
    const info = _bgpSessionInfo.get(tk);
    if (info) {
      if (info.keepaliveTimer) clearInterval(info.keepaliveTimer);
      const otherTk = info.receiverRouterId + ':' + info.senderIp;
      if (otherTk !== tk && _bgpSessionInfo.has(otherTk)) {
        const otherInfo = _bgpSessionInfo.get(otherTk);
        if (otherInfo && otherInfo.keepaliveTimer) clearInterval(otherInfo.keepaliveTimer);
        _bgpEstablished.delete(otherTk);
        _bgpSessionInfo.delete(otherTk);
        _clearBgpRoutesFromNeighbor(info.receiverRouterId, info.senderIp);
      }
    }
    _bgpEstablished.delete(tk);
    _bgpSessionInfo.delete(tk);
    _clearBgpRoutesFromNeighbor(routerId, neighborIp);
  }

  // 確立済みネイバーへ BGP UPDATE を送信し、ネイバーの RIB に登録する
  function _advertiseNetworkToNeighbors(router, prefix, mask) {
    const prefixLen = maskToPrefix(mask || _classfulMask(prefix));
    const nlri = [{ prefix, prefixLen }];
    const cfg = Storage.read(router.id, 'running') || '';
    const localAs = _getBgpAs(cfg);
    const Pcap = global.RouterPcap;
    for (const [tk, est] of _bgpEstablished) {
      if (!est || !tk.startsWith(router.id + ':')) continue;
      const info = _bgpSessionInfo.get(tk);
      if (!info) continue;
      const updatePkt = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: info.senderIp, dst: info.receiverIp,
        srcMac: info.senderMac, dstMac: info.receiverMac,
        sport: info.senderSport, dport: 179,
        nlri, nextHop: info.senderIp, asPath: [localAs], origin: 0,
      });
      Pcap.append(info.senderRouterId, updatePkt);
      if (Capture) Capture.emit(info.senderRouterId, updatePkt, { iface: info.senderIface });
      Pcap.append(info.receiverRouterId, updatePkt);
      if (Capture) Capture.emit(info.receiverRouterId, updatePkt, { iface: info.receiverIface });
      _installBgpRoutes(info.receiverRouterId, nlri, info.senderIp, [localAs], info.senderIp);
    }
    if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
  }

  // 確立済みネイバーへ BGP WITHDRAW を送信し、ネイバーの RIB から削除する
  function _withdrawNetworkFromNeighbors(router, prefix, mask) {
    const prefixLen = maskToPrefix(mask || _classfulMask(prefix));
    const withdrawn = [{ prefix, prefixLen }];
    const Pcap = global.RouterPcap;
    for (const [tk, est] of _bgpEstablished) {
      if (!est || !tk.startsWith(router.id + ':')) continue;
      const info = _bgpSessionInfo.get(tk);
      if (!info) continue;
      const withdrawPkt = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: info.senderIp, dst: info.receiverIp,
        srcMac: info.senderMac, dstMac: info.receiverMac,
        sport: info.senderSport, dport: 179,
        withdrawn, nlri: [],
      });
      Pcap.append(info.senderRouterId, withdrawPkt);
      if (Capture) Capture.emit(info.senderRouterId, withdrawPkt, { iface: info.senderIface });
      Pcap.append(info.receiverRouterId, withdrawPkt);
      if (Capture) Capture.emit(info.receiverRouterId, withdrawPkt, { iface: info.receiverIface });
      _withdrawRoutesFromNeighbor(info.receiverRouterId, withdrawn, info.senderIp);
    }
    _withdrawRoutesFromNeighbor(router.id, withdrawn, 'self');
    if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
  }
  // 受信側は自分自身の running-config に neighbor 設定があれば SYN-ACK を送信、なければ RST,ACK。
  function _onBgpSynReceived({
    receiverRouterId, receiverIface, receiverMac, receiverIp,
    senderRouterId, senderIface, senderMac, senderIp,
    senderSport, senderIsn, timerKey, router, procKey, io,
  }) {
    const Packets = global.RouterPackets;
    const Capture = global.RouterCapture;
    const Pcap    = global.RouterPcap;
    const BGP_PORT = 179;

    function emit2(pkt, srcRid, srcIfc, dstRid, dstIfc) {
      Pcap.append(srcRid, pkt);
      if (Capture) Capture.emit(srcRid, pkt, { iface: srcIfc });
      if (dstRid) {
        Pcap.append(dstRid, pkt);
        if (Capture) Capture.emit(dstRid, pkt, { iface: dstIfc });
      }
    }

    // 受信側が自分の running-config を参照して判断する
    const rcfg = Storage.read(receiverRouterId, 'running') ||
                  Storage.read(receiverRouterId, 'startup') || '';
    const hasNeighbor = /^router bgp\b/im.test(rcfg) &&
      new RegExp(`^\\s*neighbor\\s+${senderIp.replace(/\./g, '\\.')}\\s+remote-as`, 'im').test(rcfg);

    if (!hasNeighbor) {
      // neighbor 未設定 → RST,ACK を送信し 10 秒後にリトライ
      const rstPkt = Packets.buildPacket({
        proto: 'tcp', src: receiverIp, dst: senderIp,
        srcMac: receiverMac, dstMac: senderMac,
        sport: BGP_PORT, dport: senderSport,
        flags: ['rst', 'ack'], seq: 0, ack: senderIsn + 1,
      });
      emit2(rstPkt, senderRouterId, senderIface, receiverRouterId, receiverIface);
      if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
      _scheduleRetry(timerKey, router, procKey, receiverIp, io);
      return;
    }

    // neighbor 設定あり → SYN-ACK を送信
    const serverIsn = (Math.random() * 0xFFFFFF | 0) + 1;
    const synAckPkt = Packets.buildPacket({
      proto: 'tcp', src: receiverIp, dst: senderIp,
      srcMac: receiverMac, dstMac: senderMac,
      sport: BGP_PORT, dport: senderSport,
      flags: ['syn', 'ack'], seq: serverIsn, ack: senderIsn + 1,
    });
    emit2(synAckPkt, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // 送信側が ACK を返して 3-way 完了
    const ackPkt = Packets.buildPacket({
      proto: 'tcp', src: senderIp, dst: receiverIp,
      srcMac: senderMac, dstMac: receiverMac,
      sport: senderSport, dport: BGP_PORT,
      flags: ['ack'], seq: senderIsn + 1, ack: serverIsn + 1,
    });
    emit2(ackPkt, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // --- BGP OPEN 交換 ---
    const scfg = Storage.read(senderRouterId,   'running') || Storage.read(senderRouterId,   'startup') || '';

    const sAs   = _getBgpAs(scfg);
    const sRid  = _getBgpRouterId(scfg);
    const rAs   = _getBgpAs(rcfg);
    const rRid  = _getBgpRouterId(rcfg);

    // OPEN: 送信側 → 受信側
    const openS = Packets.buildPacket({
      proto: 'bgp', bgpType: 'open',
      src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
      sport: senderSport, dport: BGP_PORT,
      as: sAs, hold: 180, bgpId: sRid,
      seq: senderIsn + 1, ack: serverIsn + 1,
    });
    emit2(openS, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // OPEN: 受信側 → 送信側
    const openR = Packets.buildPacket({
      proto: 'bgp', bgpType: 'open',
      src: receiverIp, dst: senderIp, srcMac: receiverMac, dstMac: senderMac,
      sport: BGP_PORT, dport: senderSport,
      as: rAs, hold: 180, bgpId: rRid,
      seq: serverIsn + 1, ack: senderIsn + 1,
    });
    emit2(openR, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // KEEPALIVE: 送信側 → 受信側
    const kaS = Packets.buildPacket({
      proto: 'bgp', bgpType: 'keepalive',
      src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
      sport: senderSport, dport: BGP_PORT,
      seq: senderIsn + 1, ack: serverIsn + 1,
    });
    emit2(kaS, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // KEEPALIVE: 受信側 → 送信側
    const kaR = Packets.buildPacket({
      proto: 'bgp', bgpType: 'keepalive',
      src: receiverIp, dst: senderIp, srcMac: receiverMac, dstMac: senderMac,
      sport: BGP_PORT, dport: senderSport,
      seq: serverIsn + 1, ack: senderIsn + 1,
    });
    emit2(kaR, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // OPEN Message 受信ログ（送信側ターミナル）
    io.println(`%BGP-5-OPEN: OPEN Message received from ${receiverIp}: AS ${rAs}, Hold Time ${180}, BGP Router-ID ${rRid}`);
    io.println(`%BGP-5-OPEN: OPEN Message sent to ${receiverIp}: AS ${sAs}, Hold Time ${180}, BGP Router-ID ${sRid}`);
    io.println(`%BGP-5-ADJCHANGE: neighbor ${receiverIp} Up`);

    // 確立済みに登録しリトライタイマーをキャンセル
    _bgpEstablished.set(timerKey, true);
    // ルータ種別ごとにKEEPALIVE間隔を決定
    const senderOs = (router && router.os) || 'ios-xe';
    const interval = senderOs === 'junos' ? 30000 : 60000;
    // 既存タイマーがあればクリア
    if (_bgpSessionInfo.has(timerKey) && _bgpSessionInfo.get(timerKey).keepaliveTimer) {
      clearInterval(_bgpSessionInfo.get(timerKey).keepaliveTimer);
    }
    // KEEPALIVE送信タイマー
    const keepaliveTimer = setInterval(() => {
      const ka = Packets.buildPacket({
        proto: 'bgp', bgpType: 'keepalive',
        src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
        sport: senderSport, dport: BGP_PORT,
        seq: senderIsn + 1, ack: serverIsn + 1,
      });
      emit2(ka, senderRouterId, senderIface, receiverRouterId, receiverIface);
    }, interval);
    // セッション情報を両方向分保存（UPDATE 再広報に使用）
    _bgpSessionInfo.set(timerKey, {
      establishedAt: Date.now(), keepaliveTimer,
      senderRouterId, senderIface, senderMac, senderIp, senderSport,
      receiverRouterId, receiverIface, receiverMac, receiverIp,
      senderAs, receiverAs: rAs,
    });
    const reverseTk = receiverRouterId + ':' + senderIp;
    _bgpEstablished.set(reverseTk, true);
    _bgpSessionInfo.set(reverseTk, {
      establishedAt: Date.now(), keepaliveTimer: null,
      senderRouterId: receiverRouterId, senderIface: receiverIface, senderMac: receiverMac, senderIp: receiverIp, senderSport: BGP_PORT,
      receiverRouterId: senderRouterId, receiverIface: senderIface, receiverMac: senderMac, receiverIp: senderIp,
      senderAs: rAs, receiverAs: sAs,
    });
    if (_bgpRetryTimers.has(timerKey)) {
      clearTimeout(_bgpRetryTimers.get(timerKey));
      _bgpRetryTimers.delete(timerKey);
    }

    // BGP UPDATE 交換: 各ルータの network 文を相手に広報する
    const sNetworks = _getBgpNetworks(scfg);
    const rNetworks = _getBgpNetworks(rcfg);
    if (sNetworks.length > 0) {
      const updS = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
        sport: senderSport, dport: BGP_PORT,
        nlri: sNetworks.map(n => ({ prefix: n.prefix, prefixLen: n.prefixLen })),
        nextHop: senderIp, asPath: [sAs], origin: 0,
      });
      emit2(updS, senderRouterId, senderIface, receiverRouterId, receiverIface);
      _installBgpRoutes(receiverRouterId, sNetworks, senderIp, [sAs], senderIp);
      _installBgpRoutes(senderRouterId, sNetworks, '0.0.0.0', [], 'self');
    }
    if (rNetworks.length > 0) {
      const updR = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: receiverIp, dst: senderIp, srcMac: receiverMac, dstMac: senderMac,
        sport: BGP_PORT, dport: senderSport,
        nlri: rNetworks.map(n => ({ prefix: n.prefix, prefixLen: n.prefixLen })),
        nextHop: receiverIp, asPath: [rAs], origin: 0,
      });
      emit2(updR, senderRouterId, senderIface, receiverRouterId, receiverIface);
      _installBgpRoutes(senderRouterId, rNetworks, receiverIp, [rAs], receiverIp);
      _installBgpRoutes(receiverRouterId, rNetworks, '0.0.0.0', [], 'self');
    }

    if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
  }

  // BGP neighbor 設定時に TCP 3-way handshake (port 179) を自動実行
  function _triggerBgpTcp(router, procKey, neighborIp, io) {
    const Sender = global.RouterSender;
    const Packets = global.RouterPackets;
    const Capture = global.RouterCapture;
    const Pcap    = global.RouterPcap;
    if (!Sender || !Packets || !Pcap) return;

    const timerKey = router.id + ':' + neighborIp;

    // 既に確立済みならスキップ
    if (_bgpEstablished.get(timerKey)) return;

    const cfg = Storage.read(router.id, 'running') || '';

    // update-source IF がある場合はそのIPを使う
    const usSrc = (() => {
      const usM = cfg.match(new RegExp(`neighbor\\s+${neighborIp}\\s+update-source\\s+(\\S+)`, 'i'));
      if (!usM) return null;
      const usIface = usM[1];
      const ifaces = parseInterfaces(cfg);
      const blk = ifaces.find(f => f.name.toLowerCase().startsWith(usIface.toLowerCase()));
      return blk ? getIfaceIp(blk) : null;
    })();

    // 同一サブネット IF か最初の物理 IF から送信元を選ぶ
    const srcIp = usSrc || (() => {
      const nOcts = neighborIp.split('.').map(Number);
      const ifaces = parseInterfaces(cfg);
      for (const blk of ifaces) {
        if (/^loopback/i.test(blk.name)) continue;
        const ip = getIfaceIp(blk);
        if (!ip) continue;
        const mask = getIfaceMask(blk);
        if (mask) {
          const mOcts = mask.split('.').map(Number);
          const iOcts = ip.split('.').map(Number);
          if (iOcts.every((b, i) => (b & mOcts[i]) === (nOcts[i] & mOcts[i]))) return ip;
        }
      }
      for (const blk of ifaces) {
        if (/^loopback/i.test(blk.name)) continue;
        const ip = getIfaceIp(blk);
        if (ip) return ip;
      }
      return null;
    })();

    if (!srcIp) { _scheduleRetry(timerKey, router, procKey, neighborIp, io); return; }

    const ifaceMap = global.RouterSender ? (() => {
      // getIfaceMap は sender の内部関数なので自前でパース
      const map = {};
      parseInterfaces(cfg).forEach(blk => {
        const ip = getIfaceIp(blk);
        if (ip) map[ip] = blk.name;
      });
      return map;
    })() : {};
    const iface = ifaceMap[srcIp] || null;

    // ARP 解決
    const dstMac = Sender.resolveArp(router, srcIp, neighborIp, null);
    if (!dstMac) { _scheduleRetry(timerKey, router, procKey, neighborIp, io); return; }

    const rIdx = topoIdx(router.id);
    const names = (cfg.match(/^interface\s+(\S+)/gim) || []).map(l => l.replace(/^interface\s+/i,'').trim());
    const ifaceIdx = iface ? Math.max(0, names.findIndex(n => n.toLowerCase() === iface.toLowerCase())) : 0;
    const srcMac = Packets.buildIfaceMac(rIdx, ifaceIdx);

    const sport = 1024 + Math.floor(Math.random() * 60000);
    const isn = (Math.random() * 0xFFFFFF | 0) + 1;
    const BGP_PORT = 179;

    const ownerCfg = (() => {
      const topo = global.TOPOLOGY;
      if (!topo) return null;
      for (const node of topo.nodes) {
        const c = Storage.read(node.id, 'running') || Storage.read(node.id, 'startup') || '';
        const ifaces2 = parseInterfaces(c);
        for (const blk of ifaces2) {
          if (getIfaceIp(blk) === neighborIp) return { routerId: node.id, iface: blk.name, cfg: c };
        }
      }
      return null;
    })();

    const ownerMac = dstMac;
    const ownerIface = ownerCfg ? ownerCfg.iface : null;
    const ownerRouterId = ownerCfg ? ownerCfg.routerId : null;

    function emit2(pkt, srcRid, srcIfc, dstRid, dstIfc) {
      Pcap.append(srcRid, pkt);
      if (Capture) Capture.emit(srcRid, pkt, { iface: srcIfc });
      if (dstRid) {
        Pcap.append(dstRid, pkt);
        if (Capture) Capture.emit(dstRid, pkt, { iface: dstIfc });
      }
    }

    // 1. SYN
    const synPkt = Packets.buildPacket({
      proto: 'tcp', src: srcIp, dst: neighborIp, srcMac, dstMac: ownerMac,
      sport, dport: BGP_PORT, flags: ['syn'], seq: isn, ack: 0,
    });
    emit2(synPkt, router.id, iface, ownerRouterId, ownerIface);

    // 受信側ルータが存在しない場合はリトライ
    if (!ownerRouterId) { _scheduleRetry(timerKey, router, procKey, neighborIp, io); return; }

    // 受信側ルータが SYN を受け取り、自分自身の config を確認して応答する
    _onBgpSynReceived({
      receiverRouterId: ownerRouterId,
      receiverIface:    ownerIface,
      receiverMac:      ownerMac,
      receiverIp:       neighborIp,
      senderRouterId:   router.id,
      senderIface:      iface,
      senderMac:        srcMac,
      senderIp:         srcIp,
      senderSport:      sport,
      senderIsn:        isn,
      timerKey, router, procKey, io,
    });
  }

  // interface ブロックから IP を取得
  function getIfaceIp(blk) {
    for (const l of blk.lines) {
      const m = l.trim().match(/^ip\s+address\s+([\d.]+)/i);
      if (m) return m[1];
    }
    return null;
  }
  function getIfaceMask(blk) {
    for (const l of blk.lines) {
      const m = l.trim().match(/^ip\s+address\s+[\d.]+\s+([\d.]+)/i);
      if (m) return m[1];
    }
    return null;
  }
  // 'router bgp 65001' ブロック内の行を更新/追加する
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

  // router プロセスブロック内のマッチ行を1行削除する
  function _removeRouterLine(router, procKey, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+${procKey.replace(/\s+/g, '\\s+')}\\s*$`, 'i');
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) {
        return !matchRe.test(t.trim());
      }
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // router プロセスブロック内のマッチ行を複数削除する（正規表現が部分一致する全行）
  function _removeRouterLines(router, procKey, matchRe) {
    _removeRouterLine(router, procKey, matchRe);
  }

  // router プロセスブロックを丸ごと削除する
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

  // ------- show running-config 整形出力 -------
  // interface ブロックを Loopback → それ以外 (GigabitEthernet 等) の順に並び替えて出力
  function printRunningConfig(cfg, router, io) {
    const host = getHostname(cfg) || router.hostname || router.id;
    io.println('Building configuration...');
    io.println('');
    io.println('Current configuration : ' + (cfg ? cfg.length : 0) + ' bytes');
    io.println('!');
    io.println('! Last configuration change at ' + new Date().toUTCString());
    io.println('!');
    io.println('version 17.15');
    io.println('!');
    io.println('hostname ' + host);
    io.println('!');

    // interface / router ブロック以外の行と各ブロックを分離して再構築
    const lines = (cfg || '').split('\n');
    const nonIfLines = [];   // interface / router ブロック以外
    const ifBlocks = [];     // [{header, lines[]}]
    const routerBlocks = []; // [{header, lines[]}]  router bgp 等
    let curBlock = null;
    let curType = null; // 'if' | 'router'
    for (const raw of lines) {
      const im = raw.match(/^interface\s+(\S+)/i);
      const rm = raw.match(/^router\s+\S+/i);
      if (im) {
        curBlock = { header: raw, lines: [] };
        ifBlocks.push(curBlock); curType = 'if'; continue;
      }
      if (rm) {
        curBlock = { header: raw, lines: [] };
        routerBlocks.push(curBlock); curType = 'router'; continue;
      }
      if (curBlock) {
        if (raw !== '' && !/^[ \t!]/.test(raw)) {
          curBlock = null; curType = null;
          // hostname は固定出力済みなのでスキップ
          if (!/^hostname\s+/i.test(raw)) nonIfLines.push(raw);
        } else {
          curBlock.lines.push(raw);
        }
      } else {
        if (!/^hostname\s+/i.test(raw)) nonIfLines.push(raw);
      }
    }

    // Loopback を先、それ以外を後ろに並べ替え
    ifBlocks.sort((a, b) => {
      const aLo = /^interface\s+loopback/i.test(a.header) ? 0 : 1;
      const bLo = /^interface\s+loopback/i.test(b.header) ? 0 : 1;
      return aLo - bLo;
    });

    nonIfLines.forEach(l => { if (l.trim() !== '') io.println(l); });
    io.println('!');
    ifBlocks.forEach(blk => {
      const expandedName = expandIfName(blk.header.replace(/^interface\s+/i, '').trim());
      io.println('interface ' + expandedName);
      blk.lines.forEach(l => { if (l.trim() !== '') io.println(l); });
      io.println('!');
    });
    routerBlocks.forEach(blk => {
      io.println(blk.header.trimEnd());
      blk.lines.forEach(l => { if (l.trim() !== '') io.println(l); });
      io.println('!');
    });

    if (cfg && !/^end\s*$/im.test(cfg)) io.println('end');
    io.println('');
  }

  // ------- show ip bgp (簡易) -------
  function showIpBgp(args, router, cfg, io) {
    const sub = args[0] ? args[0].toLowerCase() : '';

    // running-config から router bgp ブロックを解析
    const bgpM = cfg.match(/^router\s+bgp\s+(\d+)\s*$/im);
    if (!bgpM) {
      io.println('% BGP not active');
      return;
    }
    const asn = bgpM[1];

    // bgp router-id を取得
    const ridM = cfg.match(/^\s+bgp\s+router-id\s+([\d.]+)/im);
    const routerId = ridM ? ridM[1] : '0.0.0.0';

    // neighbor remote-as 行を収集
    const neighbors = [];
    const nRe = /^\s+neighbor\s+([\d.]+)\s+remote-as\s+(\d+)/gim;
    let nm;
    while ((nm = nRe.exec(cfg)) !== null) {
      neighbors.push({ ip: nm[1], as: nm[2] });
    }

    if (sub === 'summary') {
      io.println(`BGP router identifier ${routerId}, local AS number ${asn}`);
      io.println('BGP table version is 1, main routing table version 1');
      io.println('');
      io.println('Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ  Up/Down  State/PfxRcd');
      neighbors.forEach(n => {
        const ip   = n.ip.padEnd(15);
        const as   = n.as.padStart(6);
        const tk   = router.id + ':' + n.ip;
        const est  = _bgpEstablished.get(tk);
        const info = _bgpSessionInfo.get(tk);
        let updown = 'never   ';
        let statePfx = 'Idle';
        if (est && info) {
          const sec = Math.floor((Date.now() - info.establishedAt) / 1000);
          const d = Math.floor(sec / 86400);
          const h = Math.floor((sec % 86400) / 3600);
          const m = Math.floor((sec % 3600) / 60);
          const s = sec % 60;
          updown = d > 0
            ? `${d}d${String(h).padStart(2,'0')}h    `
            : `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
          const pfxCount = (_bgpRib.get(router.id) || []).filter(e => e.neighborIp === n.ip).length;
          statePfx = String(pfxCount);
        }
        io.println(`${ip} 4 ${as}       0       0      0    0    0 ${updown}  ${statePfx}`);
      });
      io.println('');
      return;
    }

    io.println(`BGP table version is 1, local router ID ${routerId}`);
    io.println('Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,');
    io.println('Origin codes: i - IGP, e - EGP, ? - incomplete');
    io.println('');
    io.println('   Network          Next Hop        Metric LocPrf Weight Path');
    const rib = _bgpRib.get(router.id) || [];
    if (rib.length === 0) {
      io.println('% No BGP network entries');
      return;
    }
    rib.forEach(e => {
      const isSelf = e.neighborIp === 'self';
      const net = `${e.prefix}/${e.prefixLen}`.padEnd(17);
      const nh = (isSelf ? '0.0.0.0' : e.nextHop).padEnd(15);
      const weight = isSelf ? '32768' : '0';
      const lPrf = isSelf ? String(32768).padStart(6) : '      ';
      const path = e.asPath.join(' ');
      io.println(`*>  ${net} ${nh}          0 ${lPrf} ${weight.padStart(6)} ${path} ${e.origin}`);
    });
  }

  // ------- メインディスパッチャ -------
  // parts[0] = 動詞（'show' / 'write' / ...）
  function handleCommand(parts, state, io) {
    const router = state.router;
    const verb = (parts[0] || '').toLowerCase();

    // ============================================================
    // configure モード内ハンドラ
    // state.configMode: null | 'global' | 'if' | 'router'
    // state.configIface: 編集中のインタフェース名 (config-if 時のみ)
    // state.configRouter: 編集中のルータプロセス名 e.g. 'bgp 65001' (config-router 時のみ)
    // ============================================================
    if (state.configMode) {
      // exit / end は両モードで共通
      if (verb === 'end') {
        state.configMode = null;
        state.configIface = null;
        return true;
      }
      if (verb === 'exit') {
        if (state.configMode === 'if' || state.configMode === 'router') {
          state.configMode = 'global';
          state.configIface = null;
          state.configRouter = null;
        } else {
          state.configMode = null;
        }
        return true;
      }

      // ---------- config-if モード ----------
      if (state.configMode === 'if') {
        const ifaceName = state.configIface;

        // ip address <addr> <mask>
        if (verb === 'ip' && (parts[1] || '').toLowerCase() === 'address') {
          const addr = parts[2], mask = parts[3];
          if (!addr || !mask) { io.println('% Incomplete command.'); return true; }
          if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr) || !/^\d+\.\d+\.\d+\.\d+$/.test(mask)) {
            io.println('% Invalid address format'); return true;
          }
          _updateIfaceLine(router, ifaceName, /^ip address\s+/i, `ip address ${addr} ${mask}`);
          // GARP 送信: アドレス設定直後に Gratuitous ARP を emit
          _sendGarp(router, ifaceName, addr);
          return true;
        }

        // no ip address
        if (verb === 'no' && (parts[1] || '').toLowerCase() === 'ip' && (parts[2] || '').toLowerCase() === 'address') {
          _removeIfaceLine(router, ifaceName, /^ip address\s+/i);
          return true;
        }

        // description <text>
        if (verb === 'description') {
          const desc = parts.slice(1).join(' ');
          _updateIfaceLine(router, ifaceName, /^description\s*/i, `description ${desc}`);
          return true;
        }

        // no description
        if (verb === 'no' && (parts[1] || '').toLowerCase() === 'description') {
          _removeIfaceLine(router, ifaceName, /^description\s*/i);
          return true;
        }

        // shutdown / no shutdown
        if (verb === 'shutdown') {
          _updateIfaceLine(router, ifaceName, /^shutdown$/i, 'shutdown');
          return true;
        }
        if (verb === 'no' && (parts[1] || '').toLowerCase() === 'shutdown') {
          _removeIfaceLine(router, ifaceName, /^shutdown$/i);
          return true;
        }

        io.println(`% Invalid input in config-if mode: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-router モード ----------
      if (state.configMode === 'router') {
        const procKey = state.configRouter; // e.g. 'bgp 65001'

        // neighbor <ip> remote-as <as>
        if (verb === 'neighbor') {
          const nIp = parts[1], key2 = (parts[2] || '').toLowerCase(), val = parts[3];
          if (!nIp) { io.println('% Incomplete command.'); return true; }
          if (key2 === 'remote-as') {
            if (!val) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+remote-as\\s+`,'i'), `neighbor ${nIp} remote-as ${val}`);
            // 既存セッションを切断して再接続
            _teardownBgpSession(router.id, nIp);
            _triggerBgpTcp(router, procKey, nIp, io);
          } else if (key2 === 'description') {
            const desc = parts.slice(3).join(' ');
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+description\\s+`,'i'), `neighbor ${nIp} description ${desc}`);
          } else if (key2 === 'update-source') {
            if (!val) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+update-source\\s+`,'i'), `neighbor ${nIp} update-source ${val}`);
          } else if (key2 === 'shutdown') {
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+shutdown$`,'i'), `neighbor ${nIp} shutdown`);
          } else {
            io.println(`% Unrecognized neighbor sub-command: ${key2}`);
          }
          return true;
        }

        // no neighbor <ip> ...
        if (verb === 'no' && (parts[1] || '').toLowerCase() === 'neighbor') {
          const nIp = parts[2], key2 = (parts[3] || '').toLowerCase();
          if (!nIp) { io.println('% Incomplete command.'); return true; }
          if (!key2 || key2 === 'remote-as') {
            // remote-as なしで no neighbor → ネイバー全行削除＋セッション切断
            _removeRouterLines(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+`,'i'));
            _teardownBgpSession(router.id, nIp);
          } else {
            _removeRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+${key2}\\s*`,'i'));
          }
          return true;
        }

        // router-id <id>
        if (verb === 'router-id' || (verb === 'bgp' && (parts[1] || '').toLowerCase() === 'router-id')) {
          const rid = verb === 'bgp' ? parts[2] : parts[1];
          if (!rid) { io.println('% Incomplete command.'); return true; }
          _updateRouterLine(router, procKey, /^bgp router-id\s+/i, `bgp router-id ${rid}`);
          return true;
        }

        // network <prefix> mask <mask>
        if (verb === 'network') {
          const prefix = parts[1];
          if (!prefix) { io.println('% Incomplete command.'); return true; }
          const maskIdx = parts.findIndex(p => p.toLowerCase() === 'mask');
          const mask = maskIdx >= 0 ? parts[maskIdx + 1] : null;
          const effectiveMask = mask || _classfulMask(prefix);
          const line = mask ? `network ${prefix} mask ${mask}` : `network ${prefix}`;
          _updateRouterLine(router, procKey, new RegExp(`^network\\s+${prefix.replace(/\./g,'\\.')}\\s*`,'i'), line);
          _installBgpRoutes(router.id, [{ prefix, prefixLen: maskToPrefix(effectiveMask) }], '0.0.0.0', [], 'self');
          _advertiseNetworkToNeighbors(router, prefix, effectiveMask);
          return true;
        }

        // no network <prefix>
        if (verb === 'no' && (parts[1] || '').toLowerCase() === 'network') {
          const prefix = parts[2];
          if (!prefix) { io.println('% Incomplete command.'); return true; }
          // 削除前にマスクを取得してから config から除去
          const curCfg = Storage.read(router.id, 'running') || '';
          const netM = curCfg.match(new RegExp(`^\\s*network\\s+${prefix.replace(/\./g,'\\.')}(?:\\s+mask\\s+([\\d.]+))?`, 'im'));
          const mask = netM && netM[1] ? netM[1] : _classfulMask(prefix);
          _removeRouterLine(router, procKey, new RegExp(`^network\\s+${prefix.replace(/\./g,'\\.')}\\s*`,'i'));
          _withdrawNetworkFromNeighbors(router, prefix, mask);
          return true;
        }

        io.println(`% Invalid input in config-router mode: ${parts.join(' ')}`);
        return true;
      }

      // ---------- global config モード ----------

      // interface <name>
      if (verb === 'interface' || verb === 'int') {
        const name = parts[1];
        if (!name) { io.println('% Incomplete command.'); return true; }
        // config になければ新規作成
        const cfg = Storage.read(router.id, 'running') || '';
        const ifaces = parseInterfaces(cfg);
        const matched = ifaces.find(i =>
          i.name.toLowerCase() === name.toLowerCase() ||
          i.name.toLowerCase().startsWith(name.toLowerCase())
        );
        const resolvedName = matched ? matched.name : name;
        if (!matched) {
          // 新規インタフェースをconfigに追加
          const newCfg = cfg.trimEnd() + `\ninterface ${resolvedName}\n`;
          Storage.write(router.id, 'running', newCfg);
        }
        state.configMode = 'if';
        state.configIface = resolvedName;
        return true;
      }

      // router bgp <as-number>
      if (verb === 'router' && (parts[1] || '').toLowerCase() === 'bgp') {
        const asn = parts[2];
        if (!asn || isNaN(+asn)) { io.println('% Incomplete command: specify AS number.'); return true; }
        const procKey = `bgp ${asn}`;
        // running-config に router bgp ブロックがなければ追加
        const cfg = Storage.read(router.id, 'running') || '';
        const re = new RegExp(`^router\\s+bgp\\s+${asn}\\s*$`, 'im');
        if (!re.test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter bgp ${asn}\n`);
        }
        state.configMode = 'router';
        state.configRouter = procKey;
        return true;
      }

      // no router bgp <as-number>
      if (verb === 'no' && (parts[1] || '').toLowerCase() === 'router' && (parts[2] || '').toLowerCase() === 'bgp') {
        const asn = parts[3];
        if (!asn) { io.println('% Incomplete command.'); return true; }
        _removeRouterBlock(router, `bgp ${asn}`);
        return true;
      }

      // hostname <name>
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

      // no interface <name>
      if (verb === 'no' && (parts[1] || '').toLowerCase() === 'interface') {
        const name = parts[2];
        if (!name) { io.println('% Incomplete command.'); return true; }
        _removeIface(router, name);
        return true;
      }

      io.println(`% Invalid input in config mode: ${parts.join(' ')}`);
      return true;
    }

    // ============================================================
    // 通常 (privileged exec) モード
    // ============================================================

    // --- configure terminal ---
    if (verb === 'configure' || verb === 'conf') {
      const sub = (parts[1] || 'terminal').toLowerCase();
      if (sub === 'terminal' || sub === 'term' || sub === 't') {
        io.println('Enter configuration commands, one per line.  End with CNTL/Z or "end".');
        state.configMode = 'global';
        state.configIface = null;
        return true;
      }
      if (sub === '?') {
        io.println('  terminal   Configure from the terminal');
        return true;
      }
      io.println(`% Invalid input after 'configure ${sub}'`);
      return true;
    }

    // --- show ---
    if (verb === 'show' || verb === 'sh') {
      const sub = (parts[1] || '').toLowerCase();
      if (!sub) {
        io.println('% Incomplete command. Type "show ?" for help.');
        return true;
      }
      if (sub === '?') {
        io.println('  arp             ARP table');
        io.println('  clock           Display the system clock');
        io.println('  history         Display the session command history');
        io.println('  interfaces      Interface status and configuration');
        io.println('  ip              IP information');
        io.println('  ospf            OSPF information');
        io.println('  running-config  Current operating configuration');
        io.println('  startup-config  Contents of startup configuration');
        io.println('  version         System hardware and software status');
        return true;
      }
      const handler = showHandlers[sub];
      if (handler) {
        handler(parts.slice(2), router, io);
        return true;
      }
      io.println(`% Invalid input detected after 'show ${sub}'`);
      return true;
    }

    // --- write memory / wr ---
    if (verb === 'write' || verb === 'wr') {
      const sub = (parts[1] || 'memory').toLowerCase();
      if (sub === 'memory' || sub === 'mem' || verb === 'wr') {
        Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
        io.println('Building configuration...');
        io.println('[ok] startup-config を更新しました。');
        return true;
      }
      io.println(`% Invalid input after 'write ${sub}'`);
      return true;
    }

    // --- copy ---
    if (verb === 'copy') {
      const src = (parts[1] || '').toLowerCase();
      const dst = (parts[2] || '').toLowerCase();
      if (src === 'running-config' && dst === 'startup-config') {
        Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
        io.println('Destination filename [startup-config]? ');
        io.println('Building configuration...');
        io.println('[ok]');
        return true;
      }
      io.println(`% copy ${src} ${dst} is not supported in emulation`);
      return true;
    }

    return false; // 未知コマンドは commands.js に fallthrough
  }

  // ------- Tab 補完 -------
  // line: カーソルまでの入力文字列, router: ノード, state: セッション state
  // 戻り値: 候補文字列配列
  function complete(line, router, state) {
    const tokens = line.trimStart().split(/\s+/);
    const last = tokens[tokens.length - 1];
    const before = tokens.slice(0, -1).map(t => t.toLowerCase());

    // インターフェース名一覧をコンフィグから取得
    function ifaceNames() {
      const cfg = (Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '');
      return (cfg.match(/^interface\s+(\S+)/gim) || [])
        .map(l => l.replace(/^interface\s+/i, '').trim());
    }

    // ============================================================
    // configure モード内補完
    // ============================================================
    const mode = state && state.configMode;

    if (mode === 'if') {
      // config-if モード
      if (before.length === 0) {
        return ['ip', 'description', 'shutdown', 'no', 'exit', 'end']
          .filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if (v === 'ip' && before.length === 1)
        return ['address'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1)
        return ['ip', 'description', 'shutdown'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before[1] === 'ip' && before.length === 2)
        return ['address'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'global') {
      // global config モード
      if (before.length === 0) {
        return ['interface', 'hostname', 'router', 'no', 'exit', 'end']
          .filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if ((v === 'interface' || v === 'int') && before.length === 1)
        return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'router' && before.length === 1)
        return ['bgp'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1)
        return ['interface', 'router'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && (before[1] === 'interface' || before[1] === 'int') && before.length === 2)
        return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'no' && before[1] === 'router' && before.length === 2)
        return ['bgp'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'router') {
      // config-router モード
      if (before.length === 0) {
        return ['neighbor', 'network', 'bgp', 'no', 'exit', 'end']
          .filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if (v === 'bgp' && before.length === 1)
        return ['router-id'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'neighbor' && before.length === 2)
        return ['remote-as', 'description', 'update-source', 'shutdown']
          .filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'network' && before.length === 2)
        return ['mask'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'network' && before[2] === 'mask' && before.length === 3) {
        const masks = [
          '255.0.0.0', '255.128.0.0', '255.255.0.0', '255.255.128.0',
          '255.255.255.0', '255.255.255.128', '255.255.255.192',
          '255.255.255.224', '255.255.255.240', '255.255.255.248', '255.255.255.252',
        ];
        return masks.filter(m => m.startsWith(last));
      }
      if (v === 'no' && before.length === 1)
        return ['neighbor', 'network'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    // ============================================================
    // 通常 (privileged exec) モード補完
    // ============================================================

    // 第1トークンの補完
    if (before.length === 0) {
      const top = ['configure', 'show', 'write', 'copy', 'load-config', 'send', 'clear', 'exit', 'help'];
      return top.filter(c => c.startsWith(last.toLowerCase()));
    }

    const verb = before[0];

    // configure ...
    if (verb === 'configure' || verb === 'conf') {
      if (before.length === 1)
        return ['terminal'].filter(s => s.startsWith(last.toLowerCase()));
    }

    // show ...
    if (verb === 'show' || verb === 'sh') {
      if (before.length === 1) {
        const subs = ['arp', 'clock', 'history', 'interfaces', 'ip', 'ospf',
                      'running-config', 'startup-config', 'version'];
        return subs.filter(s => s.startsWith(last.toLowerCase()));
      }
      const sub = before[1];
      if (sub === 'running-config' || sub === 'startup-config') {
        if (before.length === 2) {
          return ['interface', '|'].filter(s => s.startsWith(last.toLowerCase()));
        }
        if (before[2] === 'interface' && before.length === 3) {
          return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
        }
        if (before[2] === '|' && before.length === 3) {
          return ['include', 'exclude', 'section'].filter(s => s.startsWith(last.toLowerCase()));
        }
      }
      if (sub === 'ip') {
        if (before.length === 2) {
          return ['interface', 'route', 'bgp'].filter(s => s.startsWith(last.toLowerCase()));
        }
        if (before[2] === 'interface' && before.length === 3) {
          return ['brief', ...ifaceNames()].filter(s => s.toLowerCase().startsWith(last.toLowerCase()));
        }
        if (before[2] === 'bgp' && before.length === 3) {
          return ['summary'].filter(s => s.startsWith(last.toLowerCase()));
        }
      }
      if (sub === 'interfaces' || sub === 'interface') {
        if (before.length === 2) {
          return ['brief', ...ifaceNames()].filter(s => s.toLowerCase().startsWith(last.toLowerCase()));
        }
      }
    }

    // write ...
    if (verb === 'write' || verb === 'wr') {
      if (before.length === 1) return ['memory'].filter(s => s.startsWith(last.toLowerCase()));
    }

    // copy ...
    if (verb === 'copy') {
      if (before.length === 1) return ['running-config'].filter(s => s.startsWith(last.toLowerCase()));
      if (before.length === 2) return ['startup-config'].filter(s => s.startsWith(last.toLowerCase()));
    }

    // send ...
    if (verb === 'send') {
      if (before.length === 1) {
        return ['icmp', 'tcp', 'udp', 'arp', 'bgp', 'ospf', 'show', 'save', 'clear', 'help']
          .filter(s => s.startsWith(last.toLowerCase()));
      }
    }

    return [];
  }

  // ページロード後に running-config の BGP neighbor を自動再起動する
  // （_bgpRetryTimers / _bgpEstablished はリロードで消えるため再トリガーが必要）
  function restoreBgpSessions(router) {
    const cfg = Storage.read(router.id, 'running') || '';
    const dummyIo = { println: () => {} };
    const lines = cfg.split('\n');
    let inBgp = false, procKey = null;
    for (const raw of lines) {
      const t = raw.trim();
      const bgpM = t.match(/^router\s+bgp\s+(\S+)/i);
      if (bgpM) { inBgp = true; procKey = `bgp ${bgpM[1]}`; continue; }
      if (inBgp) {
        // ブロック終端の判定は raw（インデント前の元行）で行う
        // t（trim済み）で判定すると全行が非空白始まりになるため誤判定する
        if (/^[^\s!]/.test(raw) && t !== '') { inBgp = false; procKey = null; continue; }
        const nM = t.match(/^neighbor\s+([\d.]+)\s+remote-as\s+\d+/i);
        if (nM && procKey) {
          const neighborIp = nM[1];
          const tk = router.id + ':' + neighborIp;
          // ページリロード後は確立済み状態をリセット
          _bgpEstablished.delete(tk);
          if (_bgpSessionInfo.has(tk) && _bgpSessionInfo.get(tk).keepaliveTimer) {
            clearInterval(_bgpSessionInfo.get(tk).keepaliveTimer);
          }
          _bgpSessionInfo.delete(tk);
          if (_bgpRetryTimers.has(tk)) { clearTimeout(_bgpRetryTimers.get(tk)); _bgpRetryTimers.delete(tk); }
          // 少し遅延させてページ表示が完了してから開始
          setTimeout(() => _triggerBgpTcp(router, procKey, neighborIp, dummyIo), 500);
        }
      }
    }
  }

  global.RouterIosXe = { handleCommand, complete, restoreBgpSessions };
})(window);

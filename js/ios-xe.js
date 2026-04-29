// IOS-XE CLI エミュレーション。
// commands.js から os === 'ios-xe' のときに呼ばれる。
//
// 公開:
//   RouterIosXe.handleCommand(parts, state, io)
//     parts: コマンドトークン配列（先頭が動詞）
//     戻り値: true=handled / false=unknown
(function (global) {
  const Storage = global.RouterStorage;

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

    // interface ブロック以外の行と interface ブロックを分離して再構築
    const lines = (cfg || '').split('\n');
    const nonIfLines = [];   // interface ブロック以外
    const ifBlocks = [];     // [{header, lines[]}]
    let curBlock = null;
    for (const raw of lines) {
      const im = raw.match(/^interface\s+(\S+)/i);
      if (im) {
        curBlock = { header: raw, lines: [] };
        ifBlocks.push(curBlock);
      } else if (curBlock) {
        // 非インデント行 (! 以外) で次セクション開始 → ブロック終了
        if (raw !== '' && !/^[ \t!]/.test(raw)) {
          curBlock = null;
          nonIfLines.push(raw);
        } else {
          curBlock.lines.push(raw);
        }
      } else {
        nonIfLines.push(raw);
      }
    }

    // Loopback を先、それ以外を後ろに並べ替え
    ifBlocks.sort((a, b) => {
      const aLo = /^interface\s+loopback/i.test(a.header) ? 0 : 1;
      const bLo = /^interface\s+loopback/i.test(b.header) ? 0 : 1;
      return aLo - bLo;
    });

    nonIfLines.forEach(l => io.println(l));
    ifBlocks.forEach(blk => {
      io.println(blk.header);
      blk.lines.forEach(l => io.println(l));
    });

    if (cfg && !/^end\s*$/im.test(cfg)) io.println('end');
    io.println('');
  }

  // ------- show ip bgp (簡易) -------
  function showIpBgp(args, router, cfg, io) {
    const sub = args[0] ? args[0].toLowerCase() : '';
    if (sub === 'summary') {
      io.println('BGP router identifier 0.0.0.0, local AS number 0');
      io.println('BGP table version is 1, main routing table version 1');
      io.println('');
      io.println('Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ  Up/Down  State/PfxRcd');
      io.println('(no BGP neighbors configured - emulated)');
      return;
    }
    io.println('BGP table version is 1, local router ID 0.0.0.0');
    io.println('Status codes: s suppressed, d damped, h history, * valid, > best, i - internal');
    io.println('');
    io.println('(no BGP entries - emulated)');
  }

  // ------- メインディスパッチャ -------
  // parts[0] = 動詞（'show' / 'write' / ...）
  function handleCommand(parts, state, io) {
    const router = state.router;
    const verb = (parts[0] || '').toLowerCase();

    // ============================================================
    // configure モード内ハンドラ
    // state.configMode: null | 'global' | 'if'
    // state.configIface: 編集中のインタフェース名 (config-if 時のみ)
    // ============================================================
    if (state.configMode) {
      // exit / end は両モードで共通
      if (verb === 'end') {
        state.configMode = null;
        state.configIface = null;
        return true;
      }
      if (verb === 'exit') {
        if (state.configMode === 'if') {
          state.configMode = 'global';
          state.configIface = null;
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
        return ['interface', 'hostname', 'no', 'exit', 'end']
          .filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if ((v === 'interface' || v === 'int') && before.length === 1)
        return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1)
        return ['interface'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && (before[1] === 'interface' || before[1] === 'int') && before.length === 2)
        return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
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

  global.RouterIosXe = { handleCommand, complete };
})(window);

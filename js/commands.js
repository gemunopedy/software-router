// CLIコマンド処理。UI（xterm）には依存せず、io.println / io.clear のみ使う。
// state は { router: <node>, inPasteMode, pasteBuffer, prompt } を持つ。
(function (global) {
  const Storage = global.RouterStorage;

  // ---- 全 OS 共通: ARP / GARP ヘルパー ----

  function _topoIdxFor(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // Cisco 形式 (IOS-XE / IOS-XR) の interface ブロックをパース
  function _parseCiscoIfaces(cfg) {
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

  function _getCiscoIfIp(iface, os) {
    for (const l of iface.lines) {
      if (os === 'ios-xr') {
        const m = l.match(/^ipv4 address\s+(\d+\.\d+\.\d+\.\d+)/i);
        if (m) return m[1];
      } else {
        const m = l.match(/^ip address\s+(\d+\.\d+\.\d+\.\d+)/i);
        if (m) return m[1];
      }
    }
    return null;
  }

  function _isCiscoShutdown(iface) {
    let down = false;
    for (const l of iface.lines) {
      if (/^shutdown$/i.test(l)) down = true;
      else if (/^no\s+shutdown$/i.test(l)) down = false;
    }
    return down;
  }

  // MAC を Cisco ドット表記で返す (例: 5000.0001.0000)
  function _ifMacStr(routerIdx, ifaceIdx) {
    const Packets = global.RouterPackets;
    if (!Packets) return '????';
    const b = Packets.buildIfaceMac(routerIdx, ifaceIdx);
    const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    return h.slice(0, 4) + '.' + h.slice(4, 8) + '.' + h.slice(8, 12);
  }

  // Cisco 形式 config から物理 IF に GARP を emit
  function _sendCiscoGarps(router, cfg) {
    const Packets = global.RouterPackets;
    const Capture = global.RouterCapture;
    if (!Packets || !Capture) return;
    const rIdx = _topoIdxFor(router.id);
    _parseCiscoIfaces(cfg).forEach((iface, ifaceIdx) => {
      if (/^loopback/i.test(iface.name)) return;
      if (_isCiscoShutdown(iface)) return;
      const ip = _getCiscoIfIp(iface, router.os);
      if (!ip) return;
      const mac = Packets.buildIfaceMac(rIdx, ifaceIdx);
      const pkt = Packets.buildPacket({ proto: 'arp', op: 1, src: ip, dst: ip, srcMac: mac });
      Capture.emit(router.id, pkt, { iface: iface.name });
    });
  }

  // Junos 形式 config から物理 IF に GARP を emit
  function _sendJunosGarps(router, cfg) {
    const Packets = global.RouterPackets;
    const Capture = global.RouterCapture;
    if (!Packets || !Capture) return;
    const rIdx = _topoIdxFor(router.id);
    const re = /\b((?:ge|xe|et|fe)-\d+\/\d+\/\d+)\s*\{[\s\S]*?address\s+([\d.]+)\/\d+/gi;
    let m, idx = 0;
    while ((m = re.exec(cfg))) {
      const mac = Packets.buildIfaceMac(rIdx, idx++);
      const pkt = Packets.buildPacket({ proto: 'arp', op: 1, src: m[2], dst: m[2], srcMac: mac });
      Capture.emit(router.id, pkt, { iface: m[1] });
    }
  }

  function getHostname(router) {
    const running = Storage.read(router.id, 'running');
    const startup = Storage.read(router.id, 'startup');
    const src = running || startup || '';
    // Cisco 形式 'hostname X' または Junos 形式 'host-name X;'
    const m = src.match(/host-?name\s+([^\s;]+)/i);
    return m ? m[1] : (router.hostname || router.id);
  }

  function buildPrompt(router, state) {
    const host = getHostname(router);
    if (router.os === 'ios-xe') {
      if (state && state.configMode === 'if')     return host + '(config-if)# ';
      if (state && state.configMode === 'router') return host + '(config-router)# ';
      if (state && state.configMode === 'global') return host + '(config)# ';
      return host + '# ';
    }
    if (router.os === 'ios-xr') {
      if (state && state.configMode === 'if')     return 'RP/0/RP0/CPU0:' + host + '(config-if)# ';
      if (state && state.configMode === 'router') return 'RP/0/RP0/CPU0:' + host + '(config-bgp)# ';
      if (state && state.configMode === 'global') return 'RP/0/RP0/CPU0:' + host + '(config)# ';
      return 'RP/0/RP0/CPU0:' + host + '# ';
    }
    if (router.os === 'junos') {
      if (state && state.configMode === 'edit') return 'root@' + host + '# ';
      return 'root@' + host + '> ';
    }
    return host + '# ';
  }

  function verifyStartupConfig(cfg) {
    const errors = [];
    if (!cfg || cfg.trim().length === 0) {
      errors.push('startup-config が空です');
      return { ok: false, errors };
    }
    const hasHostname = /^\s*hostname\s+\S+/im.test(cfg) || /host-name\s+\S+/i.test(cfg);
    if (!hasHostname) errors.push('hostname が設定されていません');
    const ciscoIfaces = [...cfg.matchAll(/^\s*interface\s+([^\r\n]+)/gim)];
    const junosIfaces = /interfaces\s*\{[\s\S]*?\b(ge|xe|et|fe|lo)-?\d/i.test(cfg);
    const hasIface = ciscoIfaces.length > 0 || junosIfaces;
    const hasIp = /(ip address|ipv4 address|address\s+\d+\.\d+\.\d+\.\d+)/i.test(cfg);
    if (!hasIface) errors.push('interface が1つも定義されていません');
    else if (!hasIp) errors.push('interface に IP アドレスが設定されていません');
    if (/<script>|<\/script>|rm -rf/i.test(cfg)) {
      errors.push('許可されていない文字列が含まれています');
    }
    return { ok: errors.length === 0, errors };
  }

  async function handleCommand(line, state, io) {
    const router = state.router;
    const raw = line.trim();

    // 設定貼り付けモード
    if (state.inPasteMode) {
      if (raw === 'EOF') {
        state.inPasteMode = false;
        const cfg = state.pasteBuffer.join('\n');
        state.pasteBuffer = [];
        Storage.write(router.id, 'running', cfg);
        io.println(`[ok] running-config を更新しました (${router.id})`);
        // GARP: 設定された物理 IF ごとに Gratuitous ARP を送信
        if (router.os === 'junos') _sendJunosGarps(router, cfg);
        else _sendCiscoGarps(router, cfg);
      } else {
        state.pasteBuffer.push(line);
      }
      return;
    }

    const parts = raw.split(/\s+/);
    const cmd = parts[0] ? parts[0].toLowerCase() : '';
    if (cmd === '') return;

    // do <exec-cmd>: config モード中でも exec コマンドを実行
    if (cmd === 'do' && state.configMode) {
      const subLine = parts.slice(1).join(' ');
      if (!subLine) return;
      const saved = state.configMode;
      state.configMode = null;
      await handleCommand(subLine, state, io);
      state.configMode = saved;
      return;
    }

    // IOS-XE は専用モジュールへ委譲
    if (router.os === 'ios-xe' && global.RouterIosXe) {
      const handled = global.RouterIosXe.handleCommand(parts, state, io);
      if (handled) return;
    }

    // IOS-XR は専用モジュールへ委譲
    if (router.os === 'ios-xr' && global.RouterIosXr) {
      const handled = global.RouterIosXr.handleCommand(parts, state, io);
      if (handled) return;
    }

    // JunOS は専用モジュールへ委譲
    if (router.os === 'junos' && global.RouterJunos) {
      const handled = global.RouterJunos.handleCommand(parts, state, io);
      if (handled) return;
    }

    if (cmd === 'help') {
      io.println('Available commands:');
      io.println(' load-config                       : 貼り付けで running-config を投入 (終端に EOF 単独行)');
      io.println(' show running-config | show startup-config');
      io.println(' show version | show interfaces brief');
      io.println(' write memory                       : running -> startup');
      io.println(' verify startup                     : 簡易起動チェック');
      io.println(' clear                              : 画面クリア');
      io.println(' help                               : このヘルプ');
      io.println('※ 別ルータへの切替は上のトポロジー図でノードをクリック');
      return;
    }

    if (raw === 'load-config') {
      state.inPasteMode = true;
      state.pasteBuffer = [];
      io.println('Enter configuration. End with a line containing only EOF');
      io.println('---- BEGIN PASTE ----');
      return;
    }

    if (raw === 'show running-config') {
      const cfg = Storage.read(router.id, 'running');
      io.println(`----- running-config (${router.id}) -----`);
      io.println(cfg || '[empty]');
      io.println('----- end -----');
      return;
    }

    if (raw === 'show startup-config') {
      const cfg = Storage.read(router.id, 'startup');
      io.println(`----- startup-config (${router.id}) -----`);
      io.println(cfg || '[empty]');
      io.println('----- end -----');
      return;
    }

    if (raw === 'write memory' || raw === 'wr' || raw === 'copy running-config startup-config') {
      Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
      io.println('Building configuration...');
      io.println('[OK]');
      return;
    }

    if (raw === 'verify startup') {
      const cfg = Storage.read(router.id, 'startup');
      io.println('[verify] startup-config を検査中...');
      const r = verifyStartupConfig(cfg);
      if (r.ok) io.println('[PASS] 起動要件を満たしています。');
      else { io.println('[FAIL] 起動に問題があります:'); r.errors.forEach(e => io.println(' - ' + e)); }
      return;
    }

    if (raw === 'show version') {
      if (router.os === 'ios-xe') io.println('Cisco IOS XE Software, Version 17.6.1 (emulated)');
      else if (router.os === 'junos') io.println('Junos OS Software, Version 22.4R1 (emulated)');
      else io.println('Cisco IOS XR Software, Version 7.6.1 (emulated)');
      return;
    }

    if (raw === 'show interfaces brief' || raw === 'show ip interface brief'
        || raw === 'show interfaces terse') {
      const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
      io.println('Interface              IP-Address          Status');
      let found = false;
      if (router.os === 'junos') {
        // Junos: interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
        const re = /\b((?:ge|xe|et|fe|lo)-\d+\/\d+\/\d+)\s*\{[\s\S]*?address\s+([\d./]+)/gi;
        let m;
        while ((m = re.exec(cfg))) {
          io.println(m[1].padEnd(22) + (m[2] || 'unassigned').padEnd(20) + 'up');
          found = true;
        }
      } else {
        const re = /interface\s+(\S+)[\s\S]*?(?:ip address\s+(\S+\s+\S+)|ipv4 address\s+(\S+))?/gim;
        let m;
        while ((m = re.exec(cfg))) {
          const name = m[1];
          const ip = m[2] || m[3] || 'unassigned';
          io.println(name.padEnd(22) + ip.padEnd(20) + 'up');
          found = true;
        }
      }
      if (!found) io.println('[no interfaces]');
      return;
    }

    if (raw === 'show arp') {
      const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
      const rIdx = _topoIdxFor(router.id);
      io.println('Protocol  Address          Age (min)  Hardware Addr   Type   Interface');
      if (router.os === 'junos') {
        const re = /\b((?:ge|xe|et|fe)-\d+\/\d+\/\d+)\s*\{[\s\S]*?address\s+([\d.]+)\/\d+/gi;
        let m, idx = 0;
        while ((m = re.exec(cfg))) {
          io.println('Internet  ' + m[2].padEnd(17) + '-          ' + _ifMacStr(rIdx, idx++).padEnd(16) + 'ARPA   ' + m[1]);
        }
      } else {
        _parseCiscoIfaces(cfg).forEach((iface, ifaceIdx) => {
          if (/^loopback/i.test(iface.name)) return;
          if (_isCiscoShutdown(iface)) return;
          const ip = _getCiscoIfIp(iface, router.os);
          if (!ip) return;
          io.println('Internet  ' + ip.padEnd(17) + '-          ' + _ifMacStr(rIdx, ifaceIdx).padEnd(16) + 'ARPA   ' + iface.name);
        });
      }
      // ダイナミックエントリ
      if (global.RouterSender && global.RouterSender.getArpEntries) {
        global.RouterSender.getArpEntries(router.id).forEach(e => {
          const macHex = Array.from(e.mac).map(b => b.toString(16).padStart(2,'0')).join('');
          const macDot = macHex.slice(0,4) + '.' + macHex.slice(4,8) + '.' + macHex.slice(8,12);
          const age = Math.floor((Date.now() - e.ts) / 60000);
          io.println('Internet  ' + e.ip.padEnd(17) + String(age).padEnd(11) + macDot.padEnd(16) + 'ARPA   ' + (e.iface || '-'));
        });
      }
      return;
    }

    // ---- ping ----
    if (cmd === 'ping') {
      const dst = parts[1];
      if (!dst || !/^\d+\.\d+\.\d+\.\d+$/.test(dst)) {
        io.println('% Usage: ping <ip> [repeat N] [source <ip>] [size N]');
        return;
      }

      // オプション解析
      let repeat = 5, srcIp = null, size = 100;
      for (let i = 2; i < parts.length - 1; i++) {
        const k = parts[i].toLowerCase();
        if (k === 'repeat')  { repeat = Math.min(1000, Math.max(1, parseInt(parts[++i], 10) || 5)); }
        else if (k === 'source') { srcIp = parts[++i]; }
        else if (k === 'size')   { size = Math.min(65507, Math.max(36, parseInt(parts[++i], 10) || 100)); }
        else if (k === 'count')  { repeat = Math.min(1000, Math.max(1, parseInt(parts[++i], 10) || 5)); } // junos
      }

      // 送信元 IP 自動選択: dst と同一サブネットのIF、なければ最初の物理IF
      const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
      if (!srcIp) {
        const dstOcts = dst.split('.').map(Number);
        const ifaces = _parseCiscoIfaces(cfg);
        outer: for (const iface of ifaces) {
          if (/^loopback|^lo/i.test(iface.name)) continue;
          if (_isCiscoShutdown(iface)) continue;
          const ip = _getCiscoIfIp(iface, router.os);
          if (!ip) continue;
          // サブネット一致確認（mask を lines から取得）
          for (const l of iface.lines) {
            const m = l.match(/^ip(?:v4)?\s+address\s+[\d.]+\s+([\d.]+)/i)
                   || l.match(/^ip(?:v4)?\s+address\s+[\d.]+\/([\d]+)/i);
            if (!m) continue;
            let maskOcts;
            if (m[1].includes('.')) {
              maskOcts = m[1].split('.').map(Number);
            } else {
              const bits = parseInt(m[1], 10);
              maskOcts = [0,0,0,0].map((_, i) => {
                const shift = Math.max(0, Math.min(8, bits - i * 8));
                return shift >= 8 ? 255 : shift > 0 ? 256 - (1 << (8 - shift)) : 0;
              });
            }
            const ipOcts = ip.split('.').map(Number);
            if (ipOcts.every((b, i) => (b & maskOcts[i]) === (dstOcts[i] & maskOcts[i]))) {
              srcIp = ip; break outer;
            }
          }
        }
        // フォールバック: 最初の物理 IF
        if (!srcIp) {
          for (const iface of ifaces) {
            if (/^loopback|^lo/i.test(iface.name)) continue;
            if (_isCiscoShutdown(iface)) continue;
            const ip = _getCiscoIfIp(iface, router.os);
            if (ip) { srcIp = ip; break; }
          }
        }
      }

      if (!srcIp) { io.println('% No source address found.'); return; }

      // ARP 解決（最大5回・2秒間隔、試行ごとに '.' を出力）
      const Sender = global.RouterSender;
      const Packets = global.RouterPackets;
      const Capture = global.RouterCapture;
      const Pcap    = global.RouterPcap;

      // IOS-XE / IOS-XR / Junos ごとのヘッダ（ARP試行前に表示）
      if (router.os === 'junos') {
        io.println(`PING ${dst}: ${size} data bytes`);
      } else {
        io.println('Type escape sequence to abort.');
        io.println(`Sending ${repeat}, ${size}-byte ICMP Echos to ${dst}, timeout is 2 seconds:`);
      }

      let dstMac = null;
      let arpDots = 0;
      if (Sender) {
        const ARP_MAX = 5;
        const ARP_INTERVAL = 2000;
        for (let a = 0; a < ARP_MAX; a++) {
          dstMac = Sender.resolveArp(router, srcIp, dst, null);
          if (dstMac) break;
          if (router.os !== 'junos') io.print('.');
          arpDots++;
          if (a < ARP_MAX - 1) await new Promise(r => setTimeout(r, ARP_INTERVAL));
        }
      }

      // ICMP パケット生成・キャプチャ記録
      const ifaceMap = {};
      _parseCiscoIfaces(cfg).forEach(iface => {
        const ip = _getCiscoIfIp(iface, router.os);
        if (ip) ifaceMap[ip] = iface.name;
      });
      const srcIface = ifaceMap[srcIp] || null;

      let successes = 0;
      const rtts = [];
      const BCAST = Uint8Array.from([0xff,0xff,0xff,0xff,0xff,0xff]);

      for (let i = 0; i < repeat; i++) {
        const rtt = 1 + Math.floor(Math.random() * 2);
        const success = dstMac !== null;
        if (success) { successes++; rtts.push(rtt); }

        if (router.os !== 'junos') {
          io.print(success ? '!' : '.');
        }

        if (Packets && Pcap && Capture) {
          const rIdx = _topoIdxFor(router.id);
          const ifaceIdx = srcIface ? (() => {
            const names = (cfg.match(/^interface\s+(\S+)/gim) || []).map(l => l.replace(/^interface\s+/i,'').trim());
            const idx = names.findIndex(n => n.toLowerCase() === (srcIface||'').toLowerCase());
            return idx >= 0 ? idx : 0;
          })() : 0;
          const srcMac = Packets.buildIfaceMac(rIdx, ifaceIdx);
          const finalDst = dstMac || BCAST;

          // 宛先ルータの情報を取得（ICMP を双方向に記録するため）
          const dstOwner = Sender ? Sender.findOwner(dst) : null;

          // Echo Request
          const reqPkt = Packets.buildPacket({
            proto: 'icmp', src: srcIp, dst, srcMac, dstMac: finalDst,
            id: 0xBEEF, seq: i + 1,
          });
          Pcap.append(router.id, reqPkt);
          Capture.emit(router.id, reqPkt, { iface: srcIface });
          // 宛先ルータにも Request を記録
          if (dstOwner) {
            Pcap.append(dstOwner.routerId, reqPkt);
            Capture.emit(dstOwner.routerId, reqPkt, { iface: dstOwner.ifaceName });
          }

          if (success) {
            // Echo Reply (相手ルータから返る)
            const replyPkt = Packets.buildPacket({
              proto: 'icmp', src: dst, dst: srcIp, srcMac: finalDst, dstMac: srcMac,
              id: 0xBEEF, seq: i + 1,
            });
            // ICMP は type=0 (reply) にしたいが buildPacket は type=8 のみ
            // reply パケットの type バイト (Ethernet14 + IP20 = off 34) を 0 に書き換え
            replyPkt[34] = 0;
            // checksum 再計算
            let sum = 0;
            for (let j = 34; j < replyPkt.length; j += 2) {
              sum += (replyPkt[j] << 8) | (replyPkt[j+1] || 0);
            }
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            const csum = (~sum) & 0xffff;
            replyPkt[36] = (csum >> 8) & 0xff; replyPkt[37] = csum & 0xff;

            // 宛先ルータにも Reply を記録（送信元として）
            if (dstOwner) {
              Pcap.append(dstOwner.routerId, replyPkt);
              Capture.emit(dstOwner.routerId, replyPkt, { iface: dstOwner.ifaceName });
            }
            Pcap.append(router.id, replyPkt);
            Capture.emit(router.id, replyPkt, { iface: srcIface });

            if (router.os === 'junos') {
              io.println(`64 bytes from ${dst}: icmp_seq=${i+1} ttl=64 time=${rtt} ms`);
            }
          }
        }
      }

      // 統計表示（dots 行を改行で締める）
      if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
      if (router.os === 'junos') {
        io.println(`--- ${dst} ping statistics ---`);
        io.println(`${repeat} packets transmitted, ${successes} packets received, ${Math.round((repeat-successes)*100/repeat)}% packet loss`);
        if (rtts.length) {
          const min = Math.min(...rtts), max = Math.max(...rtts);
          const avg = Math.round(rtts.reduce((a,b)=>a+b,0)/rtts.length);
          io.println(`round-trip min/avg/max/stddev = ${min}/${avg}/${max}/0.000 ms`);
        }
      } else {
        io.println('');
        const pct = Math.round(successes * 100 / repeat);
        if (rtts.length) {
          const min = Math.min(...rtts), max = Math.max(...rtts);
          const avg = Math.round(rtts.reduce((a,b)=>a+b,0)/rtts.length);
          io.println(`Success rate is ${pct} percent (${successes}/${repeat}), round-trip min/avg/max = ${min}/${avg}/${max} ms`);
        } else {
          io.println(`Success rate is 0 percent (0/${repeat})`);
        }
      }
      return;
    }

    if (raw === 'clear arp') {
      const Sender = global.RouterSender;
      if (Sender) Sender.clearArpEntries(router.id);
      io.println('ARP table cleared.');
      return;
    }
    if (raw === 'clear') { io.clear(); return; }
    if (raw === 'exit') return;

    io.println('% Invalid input or unsupported command. Type "help".');
  }

  // Tab 補完: OS 別モジュールへ委譲（state を追加引数で渡す）
  function buildComplete(router, line, state) {
    if (router.os === 'ios-xe' && global.RouterIosXe && global.RouterIosXe.complete) {
      return global.RouterIosXe.complete(line, router, state);
    }
    if (router.os === 'ios-xr' && global.RouterIosXr && global.RouterIosXr.complete) {
      return global.RouterIosXr.complete(line, router, state);
    }
    if (router.os === 'junos' && global.RouterJunos && global.RouterJunos.complete) {
      return global.RouterJunos.complete(line, router, state);
    }
    // フォールバック
    const top = ['show', 'load-config', 'write', 'send', 'clear', 'exit', 'help', 'verify'];
    const token = line.trimStart().split(/\s+/)[0] || '';
    if (!line.includes(' ')) return top.filter(c => c.startsWith(token.toLowerCase()));
    return [];
  }

  global.RouterCommands = { handleCommand, buildPrompt, getHostname, buildComplete };
})(window);

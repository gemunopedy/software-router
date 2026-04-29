// CLIコマンド処理。UI（xterm）には依存せず、io.println / io.clear のみ使う。
// state は { router: <node>, inPasteMode, pasteBuffer, prompt } を持つ。
(function (global) {
  const Storage = global.RouterStorage;

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
      if (state && state.configMode === 'global') return host + '(config)# ';
      return host + '# ';
    }
    if (router.os === 'junos') return 'root@' + host + '> ';
    return 'RP/0/RP0/CPU0:' + host + '# ';
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
      } else {
        state.pasteBuffer.push(line);
      }
      return;
    }

    const parts = raw.split(/\s+/);
    const cmd = parts[0] ? parts[0].toLowerCase() : '';
    if (cmd === '') return;

    // IOS-XE は専用モジュールへ委譲
    if (router.os === 'ios-xe' && global.RouterIosXe) {
      const handled = global.RouterIosXe.handleCommand(parts, state, io);
      if (handled) return;
    }

    if (cmd === 'help') {
      io.println('Available commands:');
      io.println(' load-config                       : 貼り付けで running-config を投入 (終端に EOF 単独行)');
      io.println(' show running-config | show startup-config');
      io.println(' show version | show interfaces brief');
      io.println(' write memory                       : running -> startup');
      io.println(' verify startup                     : 簡易起動チェック');
      io.println(' send ...                           : 擬似パケット生成 → pcap に保存 (`send help`)');
      io.println(' clear                              : 画面クリア');
      io.println(' help                               : このヘルプ');
      io.println('※ 別ルータへの切替は上のトポロジー図でノードをクリック');
      return;
    }

    // パケット送信コマンド (`send ...`) は専用モジュールへ
    if (cmd === 'send' && global.RouterSender) {
      const handled = await global.RouterSender.handle(router, raw, io);
      if (handled) return;
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
      io.println(`[ok] startup-config を更新しました (${router.id})`);
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

    if (raw === 'clear') { io.clear(); return; }
    if (raw === 'exit') return;

    io.println('% Invalid input or unsupported command. Type "help".');
  }

  // Tab 補完: OS 別モジュールへ委譲（state を追加引数で渡す）
  function buildComplete(router, line, state) {
    if (router.os === 'ios-xe' && global.RouterIosXe && global.RouterIosXe.complete) {
      return global.RouterIosXe.complete(line, router, state);
    }
    // IOS-XR / Junos: 共通の最小補完
    const top = ['show', 'load-config', 'write', 'send', 'clear', 'exit', 'help', 'verify'];
    const token = line.trimStart().split(/\s+/)[0] || '';
    if (!line.includes(' ')) return top.filter(c => c.startsWith(token.toLowerCase()));
    return [];
  }

  global.RouterCommands = { handleCommand, buildPrompt, getHostname, buildComplete };
})(window);

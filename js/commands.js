// CLIコマンド処理。UI（xterm）には依存せず、io.println / io.clear のみ使う。
// state は { router: <node>, inPasteMode, pasteBuffer, prompt } を持つ。
(function (global) {
  const Storage = global.RouterStorage;

  function getHostname(router) {
    const running = Storage.read(router.id, 'running');
    const startup = Storage.read(router.id, 'startup');
    const src = running || startup || '';
    const m = src.match(/hostname\s+([^\s]+)/i);
    return m ? m[1] : (router.hostname || router.id);
  }

  function buildPrompt(router) {
    const host = getHostname(router);
    if (router.os === 'ios-xe') return host + '# ';
    return 'RP/0/RP0/CPU0:' + host + '# ';
  }

  function verifyStartupConfig(cfg) {
    const errors = [];
    if (!cfg || cfg.trim().length === 0) {
      errors.push('startup-config が空です');
      return { ok: false, errors };
    }
    if (!/^\s*hostname\s+\S+/im.test(cfg)) errors.push('hostname が設定されていません');
    const ifaces = [...cfg.matchAll(/^\s*interface\s+([^\r\n]+)/gim)];
    const hasIp = /interface[\s\S]*?(?:ip address|ipv4 address)/im.test(cfg);
    if (ifaces.length === 0) errors.push('interface が1つも定義されていません');
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
      io.println(router.os === 'ios-xe'
        ? 'Cisco IOS XE Software, Version 17.6.1 (emulated)'
        : 'Cisco IOS XR Software, Version 7.6.1 (emulated)');
      return;
    }

    if (raw === 'show interfaces brief' || raw === 'show ip interface brief') {
      const cfg = Storage.read(router.id, 'running') || Storage.read(router.id, 'startup');
      const re = /interface\s+(\S+)[\s\S]*?(?:ip address\s+(\S+\s+\S+)|ipv4 address\s+(\S+))?/gim;
      io.println('Interface              IP-Address          Status');
      let m, found = false;
      while ((m = re.exec(cfg))) {
        const name = m[1];
        const ip = m[2] || m[3] || 'unassigned';
        io.println(name.padEnd(22) + ip.padEnd(20) + 'up');
        found = true;
      }
      if (!found) io.println('[no interfaces]');
      return;
    }

    if (raw === 'clear') { io.clear(); return; }
    if (raw === 'exit') return;

    io.println('% Invalid input or unsupported command. Type "help".');
  }

  global.RouterCommands = { handleCommand, buildPrompt, getHostname };
})(window);

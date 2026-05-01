// QoS 共通モデル / パーサー補助
// CLI 実装は各 OS ファイル (ios-xe.js / ios-xr.js / junos.js) に残す。
(function (global) {
  'use strict';

  // --- 共通パーサー ---

  // Cisco 系（IOS-XE/XR 共用）
  // 'class-map [match-all|match-any] NAME' ブロックを解析
  // → [{name, matchType, matches:[{type,value}]}]
  function parseClassMaps(cfg) {
    const result = [];
    const lines = (cfg || '').split('\n');
    let cur = null;
    for (const raw of lines) {
      const t = raw.trim();
      const m = t.match(/^class-map\s+(match-(?:all|any))?\s*(\S+)/i);
      if (m) {
        cur = { name: m[2], matchType: (m[1] || 'match-all').toLowerCase(), matches: [] };
        result.push(cur);
        continue;
      }
      if (cur) {
        if (/^(end-class-map|!|exit)/i.test(t) || (/^\S/.test(t) && !/^match\s+/i.test(t))) {
          cur = null; continue;
        }
        const mm = t.match(/^match\s+(dscp|ip\s+dscp|precedence|protocol|access-group)\s+(.+)/i);
        if (mm) cur.matches.push({ type: mm[1].toLowerCase().replace(/\s+/g, ' '), value: mm[2].trim() });
      }
    }
    return result;
  }

  // 'policy-map NAME' ブロックを解析（2段ネスト: policy-map > class > actions）
  // → [{name, classes:[{name, actions:[{raw}]}]}]
  function parsePolicyMaps(cfg) {
    const result = [];
    const lines = (cfg || '').split('\n');
    let pmap = null, cls = null;
    for (const raw of lines) {
      const indent = raw.match(/^(\s*)/)[1].length;
      const t = raw.trim();
      if (!t || t === '!') { if (indent === 0) { pmap = null; cls = null; } continue; }
      if (/^policy-map\s+(\S+)/i.test(t)) {
        const pm = t.match(/^policy-map\s+(\S+)/i);
        pmap = { name: pm[1], classes: [] };
        result.push(pmap);
        cls = null;
        continue;
      }
      if (pmap && /^end-policy-map/i.test(t)) { pmap = null; cls = null; continue; }
      if (pmap && indent > 0) {
        const cm = t.match(/^class\s+(\S+)/i);
        if (cm) { cls = { name: cm[1], actions: [] }; pmap.classes.push(cls); continue; }
        if (cls && indent > 1) {
          cls.actions.push({ raw: t });
        }
      }
    }
    return result;
  }

  // interface > service-policy 行を解析
  // → [{iface, direction:'input'|'output', policyName}]
  function parseServicePolicies(cfg) {
    const result = [];
    const lines = (cfg || '').split('\n');
    let iface = null;
    for (const raw of lines) {
      const t = raw.trim();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { iface = im[1]; continue; }
      if (iface) {
        if (/^\S/.test(t) && !/^ /.test(raw)) { iface = null; continue; }
        const sp = t.match(/^service-policy\s+(input|output)\s+(\S+)/i);
        if (sp) result.push({ iface, direction: sp[1].toLowerCase(), policyName: sp[2] });
      }
    }
    return result;
  }

  // JunOS CoS パーサー
  // 'set class-of-service ...' 行を解析
  // → { classifiers:[...], schedulers:[...], schedulerMaps:[...], ifaceSchedulerMaps:[...] }
  function parseJunosCoS(cfg) {
    const classifiers = [], schedulers = [], schedulerMaps = [], ifaceSchedulerMaps = [];
    for (const raw of (cfg || '').split('\n')) {
      const t = raw.trim();
      let m;
      m = t.match(/^set class-of-service classifiers dscp (\S+) forwarding-class (\S+) loss-priority \S+ code-points (\S+)/i);
      if (m) { classifiers.push({ name: m[1], fc: m[2], codePoint: m[3] }); continue; }
      m = t.match(/^set class-of-service schedulers (\S+) transmit-rate (\S+)/i);
      if (m) { schedulers.push({ name: m[1], transmitRate: m[2] }); continue; }
      m = t.match(/^set class-of-service scheduler-maps (\S+) forwarding-class (\S+) scheduler (\S+)/i);
      if (m) { schedulerMaps.push({ mapName: m[1], fc: m[2], schedulerName: m[3] }); continue; }
      m = t.match(/^set class-of-service interfaces (\S+) scheduler-map (\S+)/i);
      if (m) { ifaceSchedulerMaps.push({ iface: m[1], mapName: m[2] }); continue; }
    }
    return { classifiers, schedulers, schedulerMaps, ifaceSchedulerMaps };
  }

  global.RouterQos = { parseClassMaps, parsePolicyMaps, parseServicePolicies, parseJunosCoS };
})(window);

// localStorage への薄いラッパ。
//  - ルータごとの startup/running config
//  - トポロジー全体（ノード/リンク定義）
// を保持する。
(function (global) {
  const PREFIX = 'virt_router';
  const TOPO_KEY = `${PREFIX}:topology`;

  function key(routerId, kind) {
    return `${PREFIX}:${routerId}:${kind}`;
  }
  function read(routerId, kind) {
    return localStorage.getItem(key(routerId, kind)) || '';
  }
  function write(routerId, kind, value) {
    localStorage.setItem(key(routerId, kind), value);
  }
  function remove(routerId, kind) {
    localStorage.removeItem(key(routerId, kind));
  }

  // ----- Topology persistence -----
  // 保存形式は { nodes:[...], links:[...] } 全体を JSON 化。
  function loadTopology(defaultTopo) {
    const raw = localStorage.getItem(TOPO_KEY);
    if (!raw) return JSON.parse(JSON.stringify(defaultTopo));
    try {
      const t = JSON.parse(raw);
      if (!t || !Array.isArray(t.nodes) || !Array.isArray(t.links)) {
        return JSON.parse(JSON.stringify(defaultTopo));
      }
      return t;
    } catch (_) {
      return JSON.parse(JSON.stringify(defaultTopo));
    }
  }
  function saveTopology(topo) {
    localStorage.setItem(TOPO_KEY, JSON.stringify(topo));
  }
  function clearTopology() {
    localStorage.removeItem(TOPO_KEY);
  }

  // 各ルータの startup-config 初期値投入（未設定のみ）
  function ensureDefaults(topology) {
    topology.nodes.forEach(n => {
      if (!read(n.id, 'startup')) write(n.id, 'startup', n.defaultConfig || '');
    });
  }

  // 全ルータの running/startup を消去
  function resetAll(topology) {
    topology.nodes.forEach(n => {
      remove(n.id, 'startup');
      remove(n.id, 'running');
    });
  }

  // 単一ルータの設定削除（ノード削除時）
  function removeRouter(routerId) {
    remove(routerId, 'startup');
    remove(routerId, 'running');
  }

  global.RouterStorage = {
    read, write, remove,
    ensureDefaults, resetAll, removeRouter,
    loadTopology, saveTopology, clearTopology,
  };
})(window);

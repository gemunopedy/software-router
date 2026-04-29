// topology / terminal-area 間をドラッグでリサイズする。
// サイズは localStorage に割合 (0~1) で保存し、ウィンドウリサイズ後も維持する。
//
// 公開:
//   RouterResize.makeDraggable(handleEl, getBefore, setSize, onEnd?)
//     — 汎用ドラッグヘルパ。capture-view.js でも利用する。
(function (global) {

  // 汎用ドラッグリサイズ
  // handleEl : ドラッグするセパレータ要素
  // getBefore: () => number   ドラッグ開始時のハンドル上側ペイン高(px)
  // setSize  : (px)  => void  移動中に呼ばれる
  // onEnd    : () => void     ドラッグ終了後フック（省略可）
  function makeDraggable(handleEl, getBefore, setSize, onEnd) {
    handleEl.style.cursor = 'ns-resize';
    handleEl.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startPx = getBefore();
      function onMove(ev) { setSize(startPx + (ev.clientY - startY)); }
      function onUp() {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        if (onEnd) onEnd();
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  }

  // ---- メイン縦分割 (topology / terminal-area) ----
  function initMain() {
    const handleEl = document.getElementById('main-resize');
    if (!handleEl) return;

    const STORE = 'router:topo-frac';

    function avail() {
      const tb = document.getElementById('toolbar');
      return window.innerHeight - tb.offsetHeight - 6; // 6px = ハンドル
    }

    function applyFrac(frac) {
      frac = Math.max(0.05, Math.min(0.95, frac));
      const topoH = Math.round(avail() * frac);
      document.body.style.gridTemplateRows =
        `auto ${topoH}px 6px ${avail() - topoH}px`;
      return frac;
    }

    // 保存値を復元（デフォルト 50%）
    const saved = parseFloat(localStorage.getItem(STORE) || '0.5');
    applyFrac(saved);

    // ウィンドウサイズ変更時は保存した割合を維持
    window.addEventListener('resize', () => {
      applyFrac(parseFloat(localStorage.getItem(STORE) || '0.5'));
      window.dispatchEvent(new Event('router:fit'));
    });

    makeDraggable(
      handleEl,
      () => document.getElementById('topology').offsetHeight,
      (px) => {
        const f = applyFrac(px / avail());
        localStorage.setItem(STORE, f);
        window.dispatchEvent(new Event('router:fit'));
      }
    );
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMain);
  } else {
    initMain();
  }

  global.RouterResize = { makeDraggable };
})(window);

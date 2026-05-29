import { useEffect, useRef } from "react";

/**
 * MatrixRain renders the iconic "digital rain" of cascading green glyphs
 * behind the rest of the UI. It uses a single full-viewport <canvas> that is
 * fixed in place and pointer-events: none, so it never interferes with the
 * app. The animation is throttled to ~30 fps and pauses while the tab is
 * hidden to keep CPU usage modest.
 */
export default function MatrixRain() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Katakana + latin digits + a sprinkling of symbols, the classic mix.
    const glyphs =
      "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ" +
      "0123456789" +
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
      "<>[]{}/\\|=+-*#$%&@";
    const glyphChars = glyphs.split("");

    const fontSize = 16; // px, also column width
    let columns = 0;
    let drops = [];
    let dpr = Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = window.innerWidth;
      const h = window.innerHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      columns = Math.ceil(w / fontSize);
      // Randomize starting y so columns don't all line up on first frame.
      drops = new Array(columns).fill(0).map(() => Math.random() * (h / fontSize));
      // Paint an opaque black backdrop once so trails fade smoothly.
      ctx.fillStyle = "#000";
      ctx.fillRect(0, 0, w, h);
    };

    resize();
    window.addEventListener("resize", resize);

    let rafId = 0;
    let lastFrame = 0;
    const frameInterval = 1000 / 30; // ~30 fps
    let running = true;

    const draw = (ts) => {
      rafId = window.requestAnimationFrame(draw);
      if (!running) return;
      if (ts - lastFrame < frameInterval) return;
      lastFrame = ts;

      const w = canvas.width / dpr;
      const h = canvas.height / dpr;

      // Translucent black overlay creates the trailing-fade effect.
      ctx.fillStyle = "rgba(0, 0, 0, 0.08)";
      ctx.fillRect(0, 0, w, h);

      ctx.font = `${fontSize}px "JetBrains Mono", "SFMono-Regular", Consolas, monospace`;
      ctx.textBaseline = "top";

      for (let i = 0; i < columns; i++) {
        const ch = glyphChars[(Math.random() * glyphChars.length) | 0];
        const x = i * fontSize;
        const y = drops[i] * fontSize;

        // Head of the stream is bright/white; the rest is the classic green.
        if (Math.random() < 0.015) {
          ctx.fillStyle = "rgba(220, 255, 230, 0.95)";
        } else {
          ctx.fillStyle = "rgba(57, 255, 130, 0.85)";
        }
        ctx.fillText(ch, x, y);

        // Reset column to top with random delay once it reaches the bottom.
        if (y > h && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i] += 1;
      }
    };

    rafId = window.requestAnimationFrame(draw);

    const onVisibility = () => {
      running = !document.hidden;
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.cancelAnimationFrame(rafId);
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return <canvas ref={canvasRef} className="matrix-rain" aria-hidden="true" />;
}

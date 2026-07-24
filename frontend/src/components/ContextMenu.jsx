import { useEffect, useRef } from "react";

/**
 * Generic right-click context menu.
 *
 * Props:
 *   items    – Array of { label, icon?, shortcut?, onClick, disabled? } or { separator: true }
 *   position – { x, y } client coordinates from the contextmenu event, or null to hide
 *   onClose  – called when the menu should be dismissed
 */
export default function ContextMenu({ items, position, onClose }) {
  const ref = useRef(null);

  useEffect(() => {
    if (!position) return;
    function handleDown(e) {
      if (ref.current && !ref.current.contains(e.target)) onClose();
    }
    function handleKey(e) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", handleDown);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleDown);
      document.removeEventListener("keydown", handleKey);
    };
  }, [position, onClose]);

  if (!position) return null;

  // Nudge menu inside the viewport if it would clip.
  const menuWidth = 230;
  const estHeight = items.filter((i) => !i.separator).length * 36 + items.filter((i) => i.separator).length * 9;
  const x = position.x + menuWidth > window.innerWidth ? Math.max(4, position.x - menuWidth) : position.x;
  const y = position.y + estHeight > window.innerHeight ? Math.max(4, position.y - estHeight) : position.y;

  return (
    <div ref={ref} className="context-menu" style={{ left: x, top: y }}>
      {items.map((item, idx) => {
        if (item.separator) return <div key={idx} className="context-menu__sep" />;
        return (
          <button
            key={idx}
            type="button"
            className="context-menu__item"
            disabled={!!item.disabled}
            onClick={() => {
              if (!item.disabled) {
                item.onClick();
                onClose();
              }
            }}
          >
            {item.icon && <span className="context-menu__icon">{item.icon}</span>}
            <span style={{ flex: 1 }}>{item.label}</span>
            {item.shortcut && <span className="context-menu__shortcut">{item.shortcut}</span>}
          </button>
        );
      })}
    </div>
  );
}

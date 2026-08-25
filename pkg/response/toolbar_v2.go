package response

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

const toolbarV2Style = `
:host {
    color-scheme: light dark;
    --launchpad-text: #102026;
    --launchpad-muted: rgba(16, 32, 38, 0.62);
    --launchpad-panel: rgba(225, 238, 240, 0.76);
    --launchpad-panel-border: rgba(255, 255, 255, 0.58);
    --launchpad-control: rgba(246, 251, 251, 0.46);
    --launchpad-control-hover: rgba(255, 255, 255, 0.7);
    --launchpad-divider: rgba(39, 69, 76, 0.14);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif;
}
* {
    box-sizing: border-box;
}
button, a {
    font: inherit;
}
#launchpad-fab {
    width: 48px;
    height: 48px;
    border: 1px solid rgba(255, 255, 255, 0.24);
    border-radius: 15px;
    background: linear-gradient(150deg, rgba(41, 48, 54, 0.94), rgba(8, 12, 16, 0.94));
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.26), inset 0 1px 0 rgba(255, 255, 255, 0.16);
    display: grid;
    grid-template-columns: repeat(3, 5px);
    grid-template-rows: repeat(3, 5px);
    place-content: center;
    gap: 3px;
    padding: 0;
    cursor: grab;
    touch-action: none;
    user-select: none;
    -webkit-user-select: none;
    transition: transform 180ms ease, box-shadow 180ms ease, background 180ms ease;
}
#launchpad-fab:hover {
    transform: scale(1.055);
    box-shadow: 0 15px 34px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2);
}
#launchpad-fab:active {
    cursor: grabbing;
    transform: scale(0.94);
}
#launchpad-fab:focus-visible,
.launchpad-action:focus-visible,
.category-chip:focus-visible,
.app-link:focus-visible,
.account-menu-item:focus-visible,
.confirm-button:focus-visible {
    outline: 3px solid rgba(10, 132, 255, 0.72);
    outline-offset: 3px;
}
.fab-dot {
    width: 5px;
    height: 5px;
    border-radius: 1.5px;
    background: rgba(255, 255, 255, 0.94);
    pointer-events: none;
}
#launchpad-overlay {
    position: fixed;
    inset: 0;
    z-index: 2147483646;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: clamp(28px, 6vw, 92px);
    background: rgba(4, 15, 23, 0);
    -webkit-backdrop-filter: blur(0) brightness(1) saturate(1);
    backdrop-filter: blur(0) brightness(1) saturate(1);
    opacity: 0;
    visibility: hidden;
    pointer-events: none;
    transition:
        opacity 240ms cubic-bezier(0.2, 0.8, 0.2, 1),
        background 240ms ease,
        visibility 0s linear 240ms,
        -webkit-backdrop-filter 260ms ease,
        backdrop-filter 260ms ease;
}
#launchpad-overlay.open {
    background: rgba(4, 15, 23, 0.3);
    -webkit-backdrop-filter: blur(22px) brightness(0.72) saturate(1.14);
    backdrop-filter: blur(22px) brightness(0.72) saturate(1.14);
    opacity: 1;
    visibility: visible;
    pointer-events: auto;
    transition-delay: 0s;
}
.launchpad-surface {
    position: relative;
    width: min(844px, calc(100vw - 96px), 132dvh);
    height: auto;
    max-height: none;
    min-height: 0;
    aspect-ratio: 844 / 577;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    color: var(--launchpad-text);
    background:
        linear-gradient(135deg, rgba(255, 255, 255, 0.28), rgba(199, 221, 224, 0.12)),
        var(--launchpad-panel);
    border: 1px solid var(--launchpad-panel-border);
    border-radius: clamp(26px, 2.4vw, 36px);
    box-shadow:
        0 34px 90px rgba(0, 0, 0, 0.32),
        inset 0 1px 0 rgba(255, 255, 255, 0.56),
        inset 0 -1px 0 rgba(50, 72, 78, 0.1);
    -webkit-backdrop-filter: blur(52px) saturate(1.34);
    backdrop-filter: blur(52px) saturate(1.34);
    opacity: 0;
    transform: translateY(18px) scale(0.955);
    transform-origin: 50% 55%;
    transition: opacity 220ms ease, transform 300ms cubic-bezier(0.16, 1, 0.3, 1);
}
.launchpad-surface:focus {
    outline: none;
}
#launchpad-overlay.open .launchpad-surface {
    opacity: 1;
    transform: translateY(0) scale(1);
}
.launchpad-header {
    position: relative;
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 64px;
    padding: 14px clamp(20px, 2.2vw, 30px) 10px;
    gap: 14px;
}
.launchpad-heading {
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 10px;
}
.launchpad-mark {
    width: 28px;
    height: 28px;
    flex: 0 0 28px;
    display: block;
    overflow: visible;
    opacity: 0.68;
}
.launchpad-title {
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 28px;
    line-height: 1.08;
    letter-spacing: -0.025em;
    font-weight: 500;
}
.launchpad-actions {
    position: relative;
    display: flex;
    align-items: center;
    gap: 8px;
}
.launchpad-action {
    width: 32px;
    height: 32px;
    flex: 0 0 32px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0;
    border: 1px solid rgba(255, 255, 255, 0.34);
    border-radius: 50%;
    color: inherit;
    background: var(--launchpad-control);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.36);
    cursor: pointer;
    transition: background 160ms ease, transform 160ms ease;
}
.launchpad-action svg {
    width: 18px;
    height: 18px;
    display: block;
    pointer-events: none;
}
.launchpad-action:hover {
    background: var(--launchpad-control-hover);
    transform: scale(1.045);
}
.account-menu {
    position: absolute;
    top: 40px;
    right: 40px;
    z-index: 4;
    min-width: 172px;
    padding: 7px;
    border: 1px solid rgba(255, 255, 255, 0.46);
    border-radius: 15px;
    background: rgba(245, 249, 249, 0.84);
    box-shadow: 0 18px 48px rgba(0, 0, 0, 0.22);
    -webkit-backdrop-filter: blur(28px) saturate(1.3);
    backdrop-filter: blur(28px) saturate(1.3);
    opacity: 0;
    visibility: hidden;
    transform: translateY(-5px) scale(0.97);
    transform-origin: top right;
    transition: opacity 150ms ease, transform 180ms ease, visibility 0s linear 180ms;
}
.account-menu.open {
    opacity: 1;
    visibility: visible;
    transform: translateY(0) scale(1);
    transition-delay: 0s;
}
.account-menu-item {
    width: 100%;
    min-height: 44px;
    padding: 9px 12px;
    border: 0;
    border-radius: 10px;
    color: #b42318;
    background: transparent;
    text-align: left;
    cursor: pointer;
    font-size: 14px;
    font-weight: 560;
}
.account-menu-item:hover {
    background: rgba(255, 59, 48, 0.1);
}
.account-menu-item.wol-link {
    display: flex;
    align-items: center;
    gap: 9px;
    color: var(--launchpad-text);
    text-decoration: none;
}
.account-menu-item.wol-link:hover {
    background: rgba(255, 255, 255, 0.16);
}
.account-menu-item.wol-link svg {
    width: 18px;
    height: 18px;
    flex: none;
}
.category-region {
    flex: 0 0 auto;
    padding: 0 clamp(20px, 2.2vw, 32px) 10px;
}
.category-list {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 36px;
    padding: 4px 0;
    overflow-x: auto;
    overscroll-behavior-x: contain;
    scrollbar-width: none;
    border-top: 1px solid var(--launchpad-divider);
    border-bottom: 1px solid var(--launchpad-divider);
}
.category-list::-webkit-scrollbar {
    display: none;
}
.category-chip {
    min-width: 76px;
    min-height: 26px;
    flex: 0 0 auto;
    padding: 4px 12px;
    border: 1px solid rgba(255, 255, 255, 0.24);
    border-radius: 10px;
    color: var(--launchpad-muted);
    background: rgba(246, 251, 251, 0.35);
    white-space: nowrap;
    cursor: pointer;
    font-size: 13px;
    font-weight: 520;
    transition: color 150ms ease, background 150ms ease, box-shadow 150ms ease, transform 150ms ease;
}
.category-chip:hover {
    color: var(--launchpad-text);
    background: rgba(255, 255, 255, 0.58);
}
.category-chip.active {
    color: var(--launchpad-text);
    border-color: rgba(255, 255, 255, 0.46);
    background: rgba(255, 255, 255, 0.56);
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.58),
        inset 0 0 0 0.5px rgba(44, 67, 73, 0.08);
}
.apps-scroll {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    overscroll-behavior: contain;
    -webkit-overflow-scrolling: touch;
    padding: 4px clamp(22px, 2.6vw, 36px) 24px;
    scrollbar-color: rgba(70, 92, 98, 0.28) transparent;
}
.apps-grid {
    display: grid;
    grid-template-columns: repeat(7, minmax(0, 1fr));
    align-content: start;
    column-gap: clamp(14px, 1.7vw, 22px);
    row-gap: clamp(14px, 1.8vh, 20px);
    padding: 6px 0 14px;
}
.app-link {
    position: relative;
    min-width: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 7px;
    color: var(--launchpad-text);
    text-decoration: none;
    text-align: center;
    border-radius: 16px;
    padding: 2px 2px 5px;
    opacity: 0;
    transform: translateY(12px) scale(0.97);
    animation: app-enter 360ms cubic-bezier(0.16, 1, 0.3, 1) forwards;
    animation-delay: calc(var(--app-index, 0) * 24ms + 80ms);
    transition: background 160ms ease, transform 160ms ease;
}
.app-link:hover {
    background: rgba(255, 255, 255, 0.18);
    transform: translateY(-2px);
}
.app-link[hidden] {
    display: none !important;
}
@keyframes app-enter {
    to {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
}
.app-icon-shell {
    position: relative;
    width: 60px;
    height: 60px;
    display: grid;
    place-items: center;
    overflow: hidden;
    border: 0;
    border-radius: 23%;
    color: #fff;
    background: transparent;
    box-shadow: 0 7px 15px rgba(27, 45, 53, 0.18);
    transition: transform 180ms cubic-bezier(0.2, 0.8, 0.2, 1), box-shadow 180ms ease;
}
.app-icon-shell.is-placeholder {
    background: var(--icon-fill, #61748a);
    box-shadow: 0 6px 13px rgba(27, 45, 53, 0.2);
}
.app-icon-shell.has-image {
    overflow: visible;
    border-radius: 0;
    box-shadow: none;
}
.app-link:hover .app-icon-shell {
    transform: scale(1.055);
    box-shadow: 0 10px 20px rgba(27, 45, 53, 0.22);
}
.app-link:hover .app-icon-shell.has-image {
    box-shadow: none;
}
.app-icon-shell::after {
    content: none;
}
.app-icon-image {
    position: relative;
    z-index: 1;
    width: 100%;
    height: 100%;
    display: block;
    object-fit: contain;
}
.app-icon-letter {
    position: relative;
    z-index: 1;
    font-size: 27px;
    line-height: 1;
    font-weight: 560;
    letter-spacing: -0.025em;
    text-shadow: none;
}
.app-label-row {
    width: 100%;
    min-width: 0;
    display: flex;
    justify-content: center;
    align-items: flex-start;
    gap: 6px;
}
.app-label {
    min-width: 0;
    max-width: 100%;
    overflow: hidden;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    font-size: 12px;
    line-height: 1.22;
    font-weight: 480;
    letter-spacing: -0.012em;
    text-wrap: balance;
}
.current-dot {
    width: 7px;
    height: 7px;
    flex: 0 0 7px;
    margin-top: 6px;
    border-radius: 50%;
    background: #20c46b;
    box-shadow: 0 0 0 3px rgba(32, 196, 107, 0.17);
}
.empty-state {
    min-height: 240px;
    display: grid;
    place-items: center;
    padding: 32px;
    color: var(--launchpad-muted);
    text-align: center;
    font-size: 16px;
}
.empty-state[hidden] {
    display: none !important;
}
.confirm-overlay {
    position: absolute;
    inset: 0;
    z-index: 8;
    display: grid;
    place-items: center;
    padding: 22px;
    border-radius: inherit;
    background: rgba(5, 14, 19, 0);
    opacity: 0;
    visibility: hidden;
    pointer-events: none;
    transition: opacity 180ms ease, background 180ms ease, visibility 0s linear 180ms;
}
.confirm-overlay.open {
    background: rgba(5, 14, 19, 0.32);
    opacity: 1;
    visibility: visible;
    pointer-events: auto;
    transition-delay: 0s;
}
.confirm-dialog {
    width: min(100%, 360px);
    padding: 26px;
    border: 1px solid rgba(255, 255, 255, 0.52);
    border-radius: 22px;
    color: var(--launchpad-text);
    background: rgba(247, 250, 250, 0.92);
    box-shadow: 0 24px 65px rgba(0, 0, 0, 0.28);
    -webkit-backdrop-filter: blur(28px);
    backdrop-filter: blur(28px);
    text-align: center;
    transform: translateY(8px) scale(0.96);
    transition: transform 220ms cubic-bezier(0.16, 1, 0.3, 1);
}
.confirm-overlay.open .confirm-dialog {
    transform: translateY(0) scale(1);
}
.confirm-title {
    margin: 0 0 9px;
    font-size: 20px;
    font-weight: 650;
}
.confirm-message {
    margin: 0 0 24px;
    color: var(--launchpad-muted);
    font-size: 14px;
    line-height: 1.5;
}
.confirm-actions {
    display: flex;
    gap: 10px;
}
.confirm-button {
    min-height: 44px;
    flex: 1;
    border: 0;
    border-radius: 12px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 590;
}
.confirm-cancel {
    color: var(--launchpad-text);
    background: rgba(94, 112, 117, 0.12);
}
.confirm-accept {
    color: #fff;
    background: #e5484d;
}
@media (max-width: 940px) {
    .apps-grid { grid-template-columns: repeat(6, minmax(0, 1fr)); }
}
@media (max-width: 840px) {
    .apps-grid { grid-template-columns: repeat(5, minmax(0, 1fr)); }
}
@media (max-width: 768px) {
    #launchpad-overlay {
        padding: 0;
        align-items: stretch;
    }
    .launchpad-surface {
        width: 100%;
        height: 100%;
        max-height: none;
        min-height: 0;
        border: 0;
        border-radius: 0;
        padding-top: env(safe-area-inset-top);
        padding-bottom: env(safe-area-inset-bottom);
    }
    .launchpad-header {
        min-height: 82px;
        padding: 18px max(18px, env(safe-area-inset-right)) 12px max(18px, env(safe-area-inset-left));
    }
    .launchpad-mark {
        width: 30px;
        height: 30px;
        flex-basis: 30px;
    }
    .launchpad-title {
        font-size: clamp(26px, 8vw, 34px);
    }
    .launchpad-action {
        width: 44px;
        height: 44px;
        flex-basis: 44px;
    }
    .account-menu {
        right: 54px;
        top: 52px;
    }
    .category-region {
        padding: 0 max(18px, env(safe-area-inset-right)) 12px max(18px, env(safe-area-inset-left));
    }
    .category-chip {
        min-width: auto;
        min-height: 44px;
        padding: 7px 16px;
    }
    .apps-scroll {
        padding: 4px max(16px, env(safe-area-inset-right)) 30px max(16px, env(safe-area-inset-left));
    }
    .apps-grid {
        grid-template-columns: repeat(4, minmax(0, 1fr));
        column-gap: 10px;
        row-gap: 24px;
    }
    .app-link {
        padding-inline: 1px;
        gap: 9px;
    }
    .app-icon-shell {
        width: clamp(58px, 18vw, 78px);
        height: clamp(58px, 18vw, 78px);
    }
    .app-label {
        font-size: clamp(12px, 3.5vw, 14px);
    }
}
@media (max-width: 350px) {
    .apps-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .launchpad-heading { gap: 10px; }
}
@media (prefers-color-scheme: dark) {
    :host {
        --launchpad-text: #f0f6f7;
        --launchpad-muted: rgba(233, 242, 244, 0.64);
        --launchpad-panel: rgba(31, 43, 49, 0.78);
        --launchpad-panel-border: rgba(255, 255, 255, 0.18);
        --launchpad-control: rgba(255, 255, 255, 0.1);
        --launchpad-control-hover: rgba(255, 255, 255, 0.17);
        --launchpad-divider: rgba(255, 255, 255, 0.13);
    }
    .account-menu,
    .confirm-dialog {
        background: rgba(37, 48, 53, 0.94);
    }
    .category-chip {
        background: rgba(255, 255, 255, 0.07);
    }
    .category-chip.active {
        border-color: rgba(255, 255, 255, 0.16);
        background: rgba(255, 255, 255, 0.14);
        box-shadow:
            inset 0 1px 0 rgba(255, 255, 255, 0.12),
            inset 0 0 0 0.5px rgba(255, 255, 255, 0.04);
    }
}
@media (prefers-reduced-motion: reduce) {
    #launchpad-overlay,
    .launchpad-surface,
    .app-link,
    .app-icon-shell,
    .account-menu,
    .confirm-overlay,
    .confirm-dialog {
        animation: none !important;
        transition-duration: 0.01ms !important;
        animation-delay: 0ms !important;
    }
    .app-link {
        opacity: 1;
        transform: none;
    }
}
`

const toolbarV2Script = `(function(window, document) {
    if (window.self !== window.top) return;
    if (document.getElementById('reauth-proxy-toolbar')) return;

    var toolbarData = __REAUTH_TOOLBAR_DATA__;
    var toolbarLabels = toolbarData.labels || {};
    var iconDragMode = toolbarData.icon_drag_mode === 'free' ? 'free' : 'corners';
    var cornerPositionStorageKey = 'reauth_proxy_toolbar_pos';
    var freePositionStorageKey = 'reauth_proxy_toolbar_free_pos';
    var toolbarMargin = 20;
    var fabSize = 48;
    var overlayOpen = false;
    var previousFocus = null;
    var originalBodyOverflow = '';
    var originalDocumentOverflow = '';

    function label(key, fallback) {
        return typeof toolbarLabels[key] === 'string' && toolbarLabels[key] ? toolbarLabels[key] : fallback;
    }
    function asString(value) {
        return typeof value === 'string' ? value : '';
    }
    function safeGetStoredItem(key) {
        try {
            return window.localStorage ? window.localStorage.getItem(key) : null;
        } catch (err) {
            return null;
        }
    }
    function safeSetStoredItem(key, value) {
        try {
            if (window.localStorage) window.localStorage.setItem(key, value);
        } catch (err) {}
    }
    function finiteNumber(value) {
        return typeof value === 'number' && isFinite(value);
    }
    function getViewport() {
        var vv = window.visualViewport;
        var width = vv ? vv.width : window.innerWidth;
        var height = vv ? vv.height : window.innerHeight;
        return {
            left: vv ? vv.offsetLeft : 0,
            top: vv ? vv.offsetTop : 0,
            width: finiteNumber(width) && width > 0 ? width : fabSize,
            height: finiteNumber(height) && height > 0 ? height : fabSize
        };
    }
    function clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }
    function clampToolbarPosition(left, top) {
        var viewport = getViewport();
        return {
            left: clamp(left, viewport.left, viewport.left + Math.max(0, viewport.width - fabSize)),
            top: clamp(top, viewport.top, viewport.top + Math.max(0, viewport.height - fabSize))
        };
    }
    function applyCoordinates(left, top) {
        var position = clampToolbarPosition(left, top);
        container.style.left = position.left + 'px';
        container.style.top = position.top + 'px';
        return position;
    }
    function normalizeCorner(position) {
        return position === 'tl' || position === 'tr' || position === 'bl' || position === 'br' ? position : 'br';
    }
    function cornerCoordinates(position) {
        var viewport = getViewport();
        position = normalizeCorner(position);
        var left = position.charAt(1) === 'l'
            ? viewport.left + toolbarMargin
            : viewport.left + viewport.width - toolbarMargin - fabSize;
        var top = position.charAt(0) === 't'
            ? viewport.top + toolbarMargin
            : viewport.top + viewport.height - toolbarMargin - fabSize;
        return clampToolbarPosition(left, top);
    }
    function applySavedPosition() {
        if (iconDragMode === 'free') {
            var raw = safeGetStoredItem(freePositionStorageKey);
            if (raw) {
                try {
                    var value = JSON.parse(raw);
                    if (value && finiteNumber(value.left) && finiteNumber(value.top)) {
                        applyCoordinates(value.left, value.top);
                        return;
                    }
                } catch (err) {}
            }
        }
        var corner = cornerCoordinates(safeGetStoredItem(cornerPositionStorageKey) || 'br');
        applyCoordinates(corner.left, corner.top);
    }
    function normalizeHost(host) {
        return asString(host).trim().toLowerCase().replace(/\.$/, '');
    }
    function ensureSlash(path) {
        path = asString(path);
        return path.endsWith('/') ? path : path + '/';
    }
    function isActiveHost(host) {
        var current = normalizeHost(toolbarData.current_host);
        var candidate = normalizeHost(host);
        return !!candidate && candidate === current;
    }
    function isActivePath(path) {
        var current = asString(toolbarData.current_path).replace(/\/$/, '');
        var candidate = asString(path).replace(/\/$/, '');
        return !!current && (candidate === current || current.indexOf(candidate + '/') === 0 || current.indexOf(candidate) === 0);
    }
    function buildHostHref(host) {
        host = asString(host).trim();
        if (!host) return '/';
        var port = window.location.port ? ':' + window.location.port : '';
        try {
            return new URL(window.location.protocol + '//' + host + port + '/').href;
        } catch (err) {
            return '/';
        }
    }
    function isAppIconSrc(value) {
        return /^data:image\//i.test(asString(value).trim());
    }
    function fallbackLetter(value) {
        var characters = Array.from(asString(value).trim());
        return characters.length ? characters[0].toUpperCase() : '•';
    }
    function iconColor(value) {
        var colors = [
            '#58718e',
            '#876956',
            '#587c70',
            '#706586',
            '#865f6b',
            '#537883',
            '#87744f',
            '#626f91'
        ];
        var hash = 0;
        value = asString(value);
        for (var i = 0; i < value.length; i++) hash = ((hash << 5) - hash + value.charCodeAt(i)) | 0;
        return colors[Math.abs(hash) % colors.length];
    }

    var container = document.createElement('div');
    container.id = 'reauth-proxy-toolbar';
    container.style.position = 'fixed';
    container.style.zIndex = '2147483647';
    container.style.width = fabSize + 'px';
    container.style.height = fabSize + 'px';
    applySavedPosition();

    var shadow = container.attachShadow({mode: 'open'});
    var style = document.createElement('style');
    style.textContent = __REAUTH_TOOLBAR_V2_STYLE__;
    shadow.appendChild(style);

    var fab = document.createElement('button');
    fab.id = 'launchpad-fab';
    fab.type = 'button';
    fab.setAttribute('aria-label', label('applications', 'Applications'));
    fab.setAttribute('aria-haspopup', 'dialog');
    fab.setAttribute('aria-expanded', 'false');
    for (var dotIndex = 0; dotIndex < 9; dotIndex++) {
        var dot = document.createElement('span');
        dot.className = 'fab-dot';
        fab.appendChild(dot);
    }
    shadow.appendChild(fab);

    var overlay = document.createElement('div');
    overlay.id = 'launchpad-overlay';
    overlay.setAttribute('aria-hidden', 'true');

    var surface = document.createElement('section');
    surface.className = 'launchpad-surface';
    surface.setAttribute('role', 'dialog');
    surface.setAttribute('aria-modal', 'true');
    surface.setAttribute('aria-labelledby', 'launchpad-title');
    surface.tabIndex = -1;

    var header = document.createElement('header');
    header.className = 'launchpad-header';
    var heading = document.createElement('div');
    heading.className = 'launchpad-heading';
    var svgNamespace = 'http://www.w3.org/2000/svg';
    var mark = document.createElementNS(svgNamespace, 'svg');
    mark.setAttribute('class', 'launchpad-mark');
    mark.setAttribute('viewBox', '0 0 56 48');
    mark.setAttribute('aria-hidden', 'true');
    mark.setAttribute('fill', 'none');
    mark.setAttribute('stroke', 'currentColor');
    mark.setAttribute('stroke-width', '7.5');
    mark.setAttribute('stroke-linecap', 'round');
    mark.setAttribute('stroke-linejoin', 'round');
    var markPath = document.createElementNS(svgNamespace, 'path');
    markPath.setAttribute('d', 'M11 39L31 6M25 6L45 39M7 34H49');
    mark.appendChild(markPath);
    var title = document.createElement('h2');
    title.id = 'launchpad-title';
    title.className = 'launchpad-title';
    title.textContent = 'Applications';
    heading.appendChild(mark);
    heading.appendChild(title);
    header.appendChild(heading);

    var actions = document.createElement('div');
    actions.className = 'launchpad-actions';
    var moreButton = document.createElement('button');
    moreButton.type = 'button';
    moreButton.className = 'launchpad-action launchpad-more';
    moreButton.setAttribute('aria-label', label('moreActions', 'More actions'));
    moreButton.setAttribute('aria-haspopup', 'menu');
    moreButton.setAttribute('aria-expanded', 'false');
    var moreIcon = document.createElementNS(svgNamespace, 'svg');
    moreIcon.setAttribute('viewBox', '0 0 24 24');
    moreIcon.setAttribute('aria-hidden', 'true');
    for (var moreDotIndex = 0; moreDotIndex < 3; moreDotIndex++) {
        var moreDot = document.createElementNS(svgNamespace, 'circle');
        moreDot.setAttribute('cx', String(6 + moreDotIndex * 6));
        moreDot.setAttribute('cy', '12');
        moreDot.setAttribute('r', '1.75');
        moreDot.setAttribute('fill', 'currentColor');
        moreIcon.appendChild(moreDot);
    }
    moreButton.appendChild(moreIcon);
    var closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'launchpad-action launchpad-close';
    closeButton.setAttribute('aria-label', label('close', 'Close'));
    var closeIcon = document.createElementNS(svgNamespace, 'svg');
    closeIcon.setAttribute('viewBox', '0 0 24 24');
    closeIcon.setAttribute('aria-hidden', 'true');
    closeIcon.setAttribute('fill', 'none');
    closeIcon.setAttribute('stroke', 'currentColor');
    closeIcon.setAttribute('stroke-width', '2.4');
    closeIcon.setAttribute('stroke-linecap', 'round');
    var closeIconPath = document.createElementNS(svgNamespace, 'path');
    closeIconPath.setAttribute('d', 'M7 7L17 17M17 7L7 17');
    closeIcon.appendChild(closeIconPath);
    closeButton.appendChild(closeIcon);
    actions.appendChild(moreButton);
    actions.appendChild(closeButton);
    header.appendChild(actions);

    var accountMenu = document.createElement('div');
    accountMenu.className = 'account-menu';
    accountMenu.setAttribute('role', 'menu');
    if (toolbarData.show_wol) {
        var wolLink = document.createElement('a');
        wolLink.href = '/__wol__';
        wolLink.className = 'account-menu-item wol-link';
        wolLink.setAttribute('role', 'menuitem');
        var wolIcon = document.createElementNS(svgNamespace, 'svg');
        wolIcon.setAttribute('viewBox', '0 0 24 24');
        wolIcon.setAttribute('fill', 'none');
        wolIcon.setAttribute('stroke', 'currentColor');
        wolIcon.setAttribute('stroke-width', '2');
        wolIcon.setAttribute('stroke-linecap', 'round');
        wolIcon.setAttribute('stroke-linejoin', 'round');
        wolIcon.setAttribute('aria-hidden', 'true');
        [['path','d','m9 10 3-3 3 3'],['path','d','M12 13V7'],['rect','width','20','height','14','x','2','y','3','rx','2'],['path','d','M12 17v4'],['path','d','M8 21h8']].forEach(function(spec){var node=document.createElementNS(svgNamespace,spec[0]);for(var index=1;index<spec.length;index+=2)node.setAttribute(spec[index],spec[index+1]);wolIcon.appendChild(node)});
        wolLink.appendChild(wolIcon);
        wolLink.appendChild(document.createTextNode(label('wol', 'Wake-on-LAN')));
        accountMenu.appendChild(wolLink);
    }
    var logoutButton = document.createElement('button');
    logoutButton.type = 'button';
    logoutButton.className = 'account-menu-item';
    logoutButton.setAttribute('role', 'menuitem');
    logoutButton.textContent = label('logout', 'Logout');
    accountMenu.appendChild(logoutButton);
    header.appendChild(accountMenu);
    surface.appendChild(header);

    var categoryRegion = document.createElement('nav');
    categoryRegion.className = 'category-region';
    categoryRegion.setAttribute('aria-label', label('applications', 'Applications'));
    var categoryList = document.createElement('div');
    categoryList.className = 'category-list';
    categoryRegion.appendChild(categoryList);
    surface.appendChild(categoryRegion);

    var appsScroll = document.createElement('div');
    appsScroll.className = 'apps-scroll';
    var appsGrid = document.createElement('div');
    appsGrid.className = 'apps-grid';
    appsScroll.appendChild(appsGrid);
    surface.appendChild(appsScroll);

    var emptyState = document.createElement('div');
    emptyState.className = 'empty-state';
    emptyState.textContent = label('noRoutesConfigured', 'No routes configured');
    emptyState.hidden = true;
    appsScroll.appendChild(emptyState);

    var confirmOverlay = document.createElement('div');
    confirmOverlay.className = 'confirm-overlay';
    confirmOverlay.setAttribute('aria-hidden', 'true');
    var confirmDialog = document.createElement('div');
    confirmDialog.className = 'confirm-dialog';
    confirmDialog.setAttribute('role', 'alertdialog');
    confirmDialog.setAttribute('aria-modal', 'true');
    confirmDialog.setAttribute('aria-labelledby', 'launchpad-confirm-title');
    confirmDialog.setAttribute('aria-describedby', 'launchpad-confirm-message');
    var confirmTitle = document.createElement('h3');
    confirmTitle.id = 'launchpad-confirm-title';
    confirmTitle.className = 'confirm-title';
    confirmTitle.textContent = label('logoutTitle', 'Logout');
    var confirmMessage = document.createElement('p');
    confirmMessage.id = 'launchpad-confirm-message';
    confirmMessage.className = 'confirm-message';
    confirmMessage.textContent = label('logoutMessage', 'Are you sure you want to logout?');
    var confirmActions = document.createElement('div');
    confirmActions.className = 'confirm-actions';
    var cancelButton = document.createElement('button');
    cancelButton.type = 'button';
    cancelButton.className = 'confirm-button confirm-cancel';
    cancelButton.textContent = label('cancel', 'Cancel');
    var acceptButton = document.createElement('button');
    acceptButton.type = 'button';
    acceptButton.className = 'confirm-button confirm-accept';
    acceptButton.textContent = label('confirm', 'Confirm');
    confirmActions.appendChild(cancelButton);
    confirmActions.appendChild(acceptButton);
    confirmDialog.appendChild(confirmTitle);
    confirmDialog.appendChild(confirmMessage);
    confirmDialog.appendChild(confirmActions);
    confirmOverlay.appendChild(confirmDialog);
    surface.appendChild(confirmOverlay);

    overlay.appendChild(surface);
    shadow.appendChild(overlay);

    var apps = [];
    var hostRules = Array.isArray(toolbarData.host_rules) ? toolbarData.host_rules : [];
    var pathRules = Array.isArray(toolbarData.rules) ? toolbarData.rules : [];
    if (hostRules.length) {
        for (var hostIndex = 0; hostIndex < hostRules.length; hostIndex++) {
            var hostRule = hostRules[hostIndex] || {};
            var host = asString(hostRule.host);
            apps.push({
                label: asString(hostRule.label) || host,
                href: buildHostHref(host),
                icon: toolbarData.show_app_icon ? asString(hostRule.favicon) : '',
                groupId: asString(hostRule.group_id).trim(),
                groupName: asString(hostRule.group_name).trim(),
                active: isActiveHost(host)
            });
        }
    } else {
        for (var pathIndex = 0; pathIndex < pathRules.length; pathIndex++) {
            var path = asString((pathRules[pathIndex] || {}).path);
            apps.push({
                label: path,
                href: ensureSlash(path),
                icon: '',
                groupId: '',
                groupName: '',
                active: isActivePath(path)
            });
        }
    }

    function createApp(app, index) {
        var link = document.createElement('a');
        link.className = 'app-link';
        link.href = app.href;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.setAttribute('data-group-key', app.groupId && app.groupName ? 'group:' + app.groupId : 'ungrouped');
        link.style.setProperty('--app-index', String(Math.min(index, 12)));
        if (app.active) {
            link.setAttribute('aria-current', 'page');
            link.setAttribute('aria-label', app.label + ', ' + label('current', 'Current application'));
        }
        var shell = document.createElement('span');
        shell.className = 'app-icon-shell';
        if (isAppIconSrc(app.icon)) {
            shell.classList.add('has-image');
            var image = document.createElement('img');
            image.className = 'app-icon-image';
            image.src = app.icon.trim();
            image.alt = '';
            image.loading = 'lazy';
            shell.appendChild(image);
        } else {
            shell.classList.add('is-placeholder');
            shell.style.setProperty('--icon-fill', iconColor(app.label));
            var letter = document.createElement('span');
            letter.className = 'app-icon-letter';
            letter.textContent = fallbackLetter(app.label);
            shell.appendChild(letter);
        }
        var labelRow = document.createElement('span');
        labelRow.className = 'app-label-row';
        var text = document.createElement('span');
        text.className = 'app-label';
        text.textContent = app.label;
        labelRow.appendChild(text);
        if (app.active) {
            var current = document.createElement('span');
            current.className = 'current-dot';
            current.title = label('current', 'Current application');
            current.setAttribute('aria-hidden', 'true');
            labelRow.appendChild(current);
        }
        link.appendChild(shell);
        link.appendChild(labelRow);
        return link;
    }

    for (var appIndex = 0; appIndex < apps.length; appIndex++) {
        appsGrid.appendChild(createApp(apps[appIndex], appIndex));
    }
    emptyState.hidden = apps.length !== 0;
    appsGrid.hidden = apps.length === 0;

    var categoryButtons = [];
    var hasEffectiveGroups = false;
    var groups = [];
    var groupIndexes = {};
    var hasUngrouped = false;
    for (var groupScan = 0; groupScan < apps.length; groupScan++) {
        var candidate = apps[groupScan];
        if (candidate.groupId && candidate.groupName) {
            hasEffectiveGroups = true;
            if (groupIndexes[candidate.groupId] === undefined) {
                groupIndexes[candidate.groupId] = groups.length;
                groups.push({id: candidate.groupId, name: candidate.groupName});
            }
        } else {
            hasUngrouped = true;
        }
    }

    function filterApps(groupKey) {
        var links = appsGrid.querySelectorAll('.app-link');
        var visibleCount = 0;
        for (var linkIndex = 0; linkIndex < links.length; linkIndex++) {
            var visible = groupKey === 'all' || links[linkIndex].getAttribute('data-group-key') === groupKey;
            links[linkIndex].hidden = !visible;
            if (visible) visibleCount++;
        }
        for (var buttonIndex = 0; buttonIndex < categoryButtons.length; buttonIndex++) {
            var selected = categoryButtons[buttonIndex].getAttribute('data-group-key') === groupKey;
            categoryButtons[buttonIndex].classList.toggle('active', selected);
            categoryButtons[buttonIndex].setAttribute('aria-pressed', selected ? 'true' : 'false');
        }
        emptyState.hidden = visibleCount !== 0;
        appsGrid.hidden = visibleCount === 0;
        appsScroll.scrollTop = 0;
    }

    function addCategory(groupKey, name, selected) {
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'category-chip' + (selected ? ' active' : '');
        button.textContent = name;
        button.setAttribute('data-group-key', groupKey);
        button.setAttribute('aria-pressed', selected ? 'true' : 'false');
        button.addEventListener('click', function() {
            filterApps(groupKey);
        });
        categoryButtons.push(button);
        categoryList.appendChild(button);
    }

    if (hasEffectiveGroups) {
        addCategory('all', label('all', 'All'), true);
        for (var groupIndex = 0; groupIndex < groups.length; groupIndex++) {
            addCategory('group:' + groups[groupIndex].id, groups[groupIndex].name, false);
        }
        if (hasUngrouped) addCategory('ungrouped', label('ungrouped', 'Ungrouped'), false);
    } else {
        categoryRegion.hidden = true;
    }

    function updateOverlayViewport() {
        var viewport = getViewport();
        overlay.style.left = viewport.left + 'px';
        overlay.style.top = viewport.top + 'px';
        overlay.style.width = viewport.width + 'px';
        overlay.style.height = viewport.height + 'px';
        overlay.style.right = 'auto';
        overlay.style.bottom = 'auto';
    }
    function lockPageScroll() {
        originalBodyOverflow = document.body.style.overflow;
        originalDocumentOverflow = document.documentElement.style.overflow;
        document.body.style.overflow = 'hidden';
        document.documentElement.style.overflow = 'hidden';
    }
    function unlockPageScroll() {
        document.body.style.overflow = originalBodyOverflow;
        document.documentElement.style.overflow = originalDocumentOverflow;
    }
    function closeAccountMenu() {
        accountMenu.classList.remove('open');
        moreButton.setAttribute('aria-expanded', 'false');
    }
    function openLaunchpad() {
        if (overlayOpen) return;
        overlayOpen = true;
        previousFocus = shadow.activeElement || document.activeElement;
        updateOverlayViewport();
        lockPageScroll();
        overlay.classList.add('open');
        overlay.setAttribute('aria-hidden', 'false');
        fab.setAttribute('aria-expanded', 'true');
        if (hasEffectiveGroups) filterApps('all');
        window.requestAnimationFrame(function() {
            surface.focus({preventScroll: true});
        });
    }
    function closeLaunchpad(restoreFocus) {
        if (!overlayOpen) return;
        closeConfirm();
        closeAccountMenu();
        overlayOpen = false;
        overlay.classList.remove('open');
        overlay.setAttribute('aria-hidden', 'true');
        fab.setAttribute('aria-expanded', 'false');
        unlockPageScroll();
        if (restoreFocus !== false) {
            window.setTimeout(function() {
                if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus({preventScroll: true});
                else fab.focus({preventScroll: true});
            }, 0);
        }
    }
    function openConfirm() {
        closeAccountMenu();
        confirmOverlay.classList.add('open');
        confirmOverlay.setAttribute('aria-hidden', 'false');
        window.requestAnimationFrame(function() {
            cancelButton.focus({preventScroll: true});
        });
    }
    function closeConfirm(restoreFocus) {
        confirmOverlay.classList.remove('open');
        confirmOverlay.setAttribute('aria-hidden', 'true');
        if (restoreFocus) moreButton.focus({preventScroll: true});
    }

    closeButton.addEventListener('click', function() {
        closeLaunchpad(true);
    });
    moreButton.addEventListener('click', function(event) {
        event.stopPropagation();
        var open = !accountMenu.classList.contains('open');
        accountMenu.classList.toggle('open', open);
        moreButton.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (open) logoutButton.focus({preventScroll: true});
    });
    logoutButton.addEventListener('click', openConfirm);
    cancelButton.addEventListener('click', function() {
        closeConfirm(true);
    });
    acceptButton.addEventListener('click', function() {
        window.location.assign('/__auth__/api/auth/logout');
    });
    confirmOverlay.addEventListener('click', function(event) {
        if (event.target === confirmOverlay) closeConfirm(true);
    });
    overlay.addEventListener('click', function(event) {
        if (event.target === overlay) closeLaunchpad(true);
    });
    surface.addEventListener('click', function(event) {
        if (!actions.contains(event.target) && !accountMenu.contains(event.target)) closeAccountMenu();
    });

    function visibleFocusable(root) {
        var candidates = root.querySelectorAll('button:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])');
        var visible = [];
        for (var i = 0; i < candidates.length; i++) {
            if (!candidates[i].hidden && candidates[i].getClientRects().length) visible.push(candidates[i]);
        }
        return visible;
    }
    document.addEventListener('keydown', function(event) {
        if (!overlayOpen) return;
        if (event.key === 'Escape') {
            event.preventDefault();
            if (confirmOverlay.classList.contains('open')) {
                closeConfirm(true);
            } else if (accountMenu.classList.contains('open')) {
                closeAccountMenu();
                moreButton.focus({preventScroll: true});
            } else {
                closeLaunchpad(true);
            }
            return;
        }
        if (event.key !== 'Tab') return;
        var focusRoot = confirmOverlay.classList.contains('open') ? confirmDialog : surface;
        var focusable = visibleFocusable(focusRoot);
        if (!focusable.length) {
            event.preventDefault();
            surface.focus();
            return;
        }
        var first = focusable[0];
        var last = focusable[focusable.length - 1];
        var active = shadow.activeElement;
        if (event.shiftKey && (active === first || !focusRoot.contains(active))) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && active === last) {
            event.preventDefault();
            first.focus();
        }
    });

    var dragState = null;
    var dragged = false;
    fab.addEventListener('pointerdown', function(event) {
        if (event.button !== 0 && event.pointerType === 'mouse') return;
        var rect = container.getBoundingClientRect();
        dragState = {
            pointerId: event.pointerId,
            startX: event.clientX,
            startY: event.clientY,
            left: rect.left,
            top: rect.top
        };
        dragged = false;
        fab.setPointerCapture(event.pointerId);
    });
    fab.addEventListener('pointermove', function(event) {
        if (!dragState || dragState.pointerId !== event.pointerId) return;
        var dx = event.clientX - dragState.startX;
        var dy = event.clientY - dragState.startY;
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) dragged = true;
        if (!dragged) return;
        event.preventDefault();
        applyCoordinates(dragState.left + dx, dragState.top + dy);
    });
    function finishDrag(event) {
        if (!dragState || dragState.pointerId !== event.pointerId) return;
        if (fab.hasPointerCapture(event.pointerId)) fab.releasePointerCapture(event.pointerId);
        dragState = null;
        if (!dragged) return;
        var rect = container.getBoundingClientRect();
        if (iconDragMode === 'free') {
            var position = applyCoordinates(rect.left, rect.top);
            safeSetStoredItem(freePositionStorageKey, JSON.stringify(position));
            return;
        }
        var viewport = getViewport();
        var horizontal = rect.left + rect.width / 2 < viewport.left + viewport.width / 2 ? 'l' : 'r';
        var vertical = rect.top + rect.height / 2 < viewport.top + viewport.height / 2 ? 't' : 'b';
        var cornerName = vertical + horizontal;
        safeSetStoredItem(cornerPositionStorageKey, cornerName);
        var corner = cornerCoordinates(cornerName);
        container.style.transition = 'left 280ms cubic-bezier(0.2, 0.8, 0.2, 1), top 280ms cubic-bezier(0.2, 0.8, 0.2, 1)';
        applyCoordinates(corner.left, corner.top);
        window.setTimeout(function() {
            container.style.transition = '';
        }, 290);
    }
    fab.addEventListener('pointerup', finishDrag);
    fab.addEventListener('pointercancel', finishDrag);
    fab.addEventListener('click', function(event) {
        if (dragged) {
            event.preventDefault();
            dragged = false;
            return;
        }
        if (overlayOpen) closeLaunchpad(true);
        else openLaunchpad();
    });

    function handleViewportChange() {
        if (!dragState) applySavedPosition();
        if (overlayOpen) updateOverlayViewport();
    }
    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', handleViewportChange);
        window.visualViewport.addEventListener('scroll', handleViewportChange);
    }
    window.addEventListener('resize', handleViewportChange);
    window.addEventListener('scroll', handleViewportChange);

    document.body.appendChild(container);
})(window, document);`

func initToolbarV2Runtime() {
	runtimeDocument := strings.Replace(toolbarV2Script, "__REAUTH_TOOLBAR_V2_STYLE__", strconv.Quote(toolbarV2Style), 1)
	runtimeDocument = strings.Replace(runtimeDocument, toolbarDataMarker, toolbarRuntimeDataExpression, 1)
	toolbarV2Runtime = []byte(strings.TrimSpace(runtimeDocument))
	digest := sha256.Sum256(toolbarV2Runtime)
	toolbarV2AssetPath = "/__assets__/toolbar/toolbar-v2." + hex.EncodeToString(digest[:]) + ".js"
	toolbarV2TemplatePrefix = `<script id="reauth-proxy-toolbar-v2-loader" src="` + toolbarV2AssetPath + `" data-toolbar='`
	toolbarV2TemplateSuffix = `' defer></script>`
}

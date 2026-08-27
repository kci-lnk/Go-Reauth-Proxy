package response

import (
	"crypto/sha256"
	"encoding/hex"
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/models"
	"html"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const toolbarTemplate = `
<script>
(function(window, document) {
    if (window.self !== window.top) return;
    if (document.getElementById('reauth-proxy-toolbar')) return;

    var container = document.createElement('div');
    container.id = 'reauth-proxy-toolbar';
    container.style.position = 'fixed';
    container.style.zIndex = '2147483647';
    container.style.fontFamily = 'ui-sans-serif, system-ui, sans-serif';

	var toolbarData = __REAUTH_TOOLBAR_DATA__;
	var toolbarLabels = toolbarData.labels || {};
    var iconDragMode = toolbarData.icon_drag_mode === 'free' ? 'free' : 'corners';
    var cornerPositionStorageKey = 'reauth_proxy_toolbar_pos';
    var freePositionStorageKey = 'reauth_proxy_toolbar_free_pos';
    var groupCollapseStorageKey = 'reauth_proxy_toolbar_groups_collapsed';
    var toolbarMargin = 20;
    var fabSize = 44;

    function safeGetStoredItem(key) {
        try {
            return window.localStorage ? window.localStorage.getItem(key) : null;
        } catch (err) {
            return null;
        }
    }

    function safeSetStoredItem(key, value) {
        try {
            if (window.localStorage) {
                window.localStorage.setItem(key, value);
            }
        } catch (err) {}
    }

    function isFiniteNumber(value) {
        return typeof value === 'number' && isFinite(value);
    }

    function getViewport() {
        var vv = window.visualViewport;
        var width = vv ? vv.width : window.innerWidth;
        var height = vv ? vv.height : window.innerHeight;
        return {
            left: vv ? vv.offsetLeft : 0,
            top: vv ? vv.offsetTop : 0,
            width: isFiniteNumber(width) && width > 0 ? width : fabSize,
            height: isFiniteNumber(height) && height > 0 ? height : fabSize
        };
    }

    function clampNumber(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    function clampToolbarPosition(left, top) {
        var viewport = getViewport();
        var minLeft = viewport.left;
        var minTop = viewport.top;
        var maxLeft = viewport.left + Math.max(0, viewport.width - fabSize);
        var maxTop = viewport.top + Math.max(0, viewport.height - fabSize);
        return {
            left: clampNumber(left, minLeft, maxLeft),
            top: clampNumber(top, minTop, maxTop)
        };
    }

    function applyCoordinates(left, top) {
        var pos = clampToolbarPosition(left, top);
        container.style.bottom = 'auto';
        container.style.right = 'auto';
        container.style.left = pos.left + 'px';
        container.style.top = pos.top + 'px';
        return pos;
    }

    function normalizeCornerPosition(pos) {
        return pos === 'tl' || pos === 'tr' || pos === 'bl' || pos === 'br' ? pos : 'br';
    }

    function getCornerCoordinates(pos) {
        var viewport = getViewport();
        pos = normalizeCornerPosition(pos);

        if (pos === 'tl') {
            return clampToolbarPosition(viewport.left + toolbarMargin, viewport.top + toolbarMargin);
        } else if (pos === 'tr') {
            return clampToolbarPosition(viewport.left + viewport.width - toolbarMargin - fabSize, viewport.top + toolbarMargin);
        } else if (pos === 'bl') {
            return clampToolbarPosition(viewport.left + toolbarMargin, viewport.top + viewport.height - toolbarMargin - fabSize);
        }
        return clampToolbarPosition(viewport.left + viewport.width - toolbarMargin - fabSize, viewport.top + viewport.height - toolbarMargin - fabSize);
    }

    function applyCornerPosition(pos) {
        pos = getCornerCoordinates(pos);
        applyCoordinates(pos.left, pos.top);
    }

    function readFreePosition() {
        var raw = safeGetStoredItem(freePositionStorageKey);
        if (!raw) return null;
        try {
            var parsed = JSON.parse(raw);
            if (!parsed || !isFiniteNumber(parsed.left) || !isFiniteNumber(parsed.top)) {
                return null;
            }
            return clampToolbarPosition(parsed.left, parsed.top);
        } catch (err) {
            return null;
        }
    }

    function writeFreePosition(left, top) {
        var pos = applyCoordinates(left, top);
        safeSetStoredItem(freePositionStorageKey, JSON.stringify({
            left: pos.left,
            top: pos.top
        }));
        return pos;
    }

    function applyFreePosition() {
        var pos = readFreePosition();
        if (!pos) {
            pos = getCornerCoordinates(safeGetStoredItem(cornerPositionStorageKey) || 'br');
        }
        applyCoordinates(pos.left, pos.top);
    }

    function applySavedToolbarPosition() {
        if (iconDragMode === 'free') {
            applyFreePosition();
            return;
        }
        applyCornerPosition(safeGetStoredItem(cornerPositionStorageKey) || 'br');
    }

    applySavedToolbarPosition();

    var shadow = container.attachShadow({mode: 'open'});

    var style = document.createElement('style');
    style.textContent = ` + "`" + `
        .dot {
            width: 8px;
            height: 8px;
            background-color: #10b981;
            border-radius: 50%;
            display: inline-block;
        }
        #fab {
            width: 44px;
            height: 44px;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            color: #fff;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: move;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(255, 255, 255, 0.1);
            user-select: none;
            transition: transform 0.2s, background 0.2s;
            position: relative;
        }
        #fab:hover {
            transform: scale(1.05);
            background: rgba(0, 0, 0, 0.95);
        }
        #fab:active {
            transform: scale(0.95);
        }
        #fab svg {
            width: 20px;
            height: 20px;
            pointer-events: none;
        }
        #menu {
            position: absolute;
            background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            width: 220px;
            display: none;
            flex-direction: column;
            overflow: hidden;
            box-sizing: border-box;
            max-height: calc(100vh - 96px);
            transform-origin: bottom right;
            opacity: 0;
            transform: scale(0.95) translateY(10px);
            transition: opacity 0.15s ease, transform 0.15s ease;
        }
        #menu.open {
            display: flex;
            opacity: 1;
            transform: scale(1) translateY(0);
        }
        .menu-item {
            padding: 10px 16px;
            color: #374151;
            text-decoration: none;
            font-size: 14px;
            border-bottom: 1px solid #f3f4f6;
            transition: background-color 0.15s, color 0.15s;
            display: flex; /* Make menu items flex containers. */
            align-items: center; /* Vertically center all content. */
            justify-content: space-between; /* Keep the path left and status/action right. */
            white-space: nowrap;
            overflow: hidden;
            position: relative;
        }
        .menu-item:last-child {
            border-bottom: none;
        }
        .menu-item:hover {
            background-color: #f9fafb;
            color: #111827;
        }
        .wol-menu-label {
            display: inline-flex;
            align-items: center;
            gap: 9px;
        }
        .wol-menu-label svg {
            width: 18px;
            height: 18px;
            flex: none;
        }
        .menu-item-icon {
            width: 18px;
            height: 18px;
            border-radius: 4px;
            object-fit: contain;
            flex-shrink: 0;
            margin-right: 10px;
            background: #f3f4f6;
        }
        .menu-item.active {
            color: #18181b;
            font-weight: 600;
        }
        .menu-item.active:hover {
            background-color: #f9fafb;
        }
        /* Path segment styles. */
        .menu-item-path {
            flex-grow: 1; /* Let the path take the remaining space. */
            overflow: hidden;
            text-overflow: ellipsis;
        }
        /* Right-side status/action styles. */
        .menu-item-right-content {
            display: flex; /* Provide flex layout for the dot/text. */
            align-items: center; /* Vertically center the dot and text. */
            gap: 6px; /* Space between the dot and Go text when active. */
            font-size: 12px; /* Right-side content size. */
            color: #6b7280; /* Default color. */
            margin-left: 12px; /* Space between path and right-side content. */
        }
        .menu-item.active .menu-item-right-content {
            color: #18181b; /* Active text color. */
        }
        .menu-item.active .menu-item-right-content .dot {
            background-color: #10b981; /* Active dot color. */
        }
        .menu-empty {
            padding: 12px 16px;
            color: #6b7280;
            font-size: 13px;
            background: #fff;
            border-bottom: 1px solid #f3f4f6;
        }
        .menu-group {
            border-bottom: 1px solid #f3f4f6;
        }
        .menu-group:last-child {
            border-bottom: none;
        }
        .menu-group-header {
            width: 100%;
            min-height: 38px;
            padding: 8px 12px;
            border: 0;
            background: #f9fafb;
            color: #374151;
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            text-align: left;
            font-size: 12px;
            font-weight: 600;
        }
        .menu-group-header:hover {
            background: #f3f4f6;
        }
        .menu-group-chevron {
            display: block;
            width: 16px;
            height: 16px;
            flex: 0 0 16px;
            align-self: center;
            transform-origin: 8px 8px;
            transition: transform 0.22s cubic-bezier(0.2, 0.8, 0.2, 1);
        }
        .menu-group:not(.collapsed) .menu-group-chevron {
            transform: rotate(90deg);
        }
        .menu-group-title {
            min-width: 0;
            flex: 1 1 auto;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .menu-group-count {
            color: #6b7280;
            font-size: 11px;
            font-weight: 500;
        }
        .menu-group-items {
            display: grid;
            grid-template-rows: 1fr;
            opacity: 1;
            transform: translateY(0);
            transition:
                grid-template-rows 0.22s cubic-bezier(0.2, 0.8, 0.2, 1),
                opacity 0.16s ease,
                transform 0.22s cubic-bezier(0.2, 0.8, 0.2, 1);
        }
        .menu-group-items-inner {
            min-height: 0;
            overflow: hidden;
        }
        .menu-group.collapsed .menu-group-items {
            grid-template-rows: 0fr;
            opacity: 0;
            transform: translateY(-4px);
            pointer-events: none;
        }
        @media (prefers-reduced-motion: reduce) {
            .menu-group-chevron,
            .menu-group-items {
                transition: none;
            }
        }
        .menu-scroll {
            flex: 1 1 auto;
            min-height: 0;
            overflow-y: auto;
            overscroll-behavior: contain;
            -webkit-overflow-scrolling: touch;
        }
        .menu-divider {
            height: 4px;
            background: #f9fafb;
            flex-shrink: 0;
        }
        .logout-btn {
            color: #ef4444;
            font-weight: 500;
        }
        .logout-btn:hover {
            background-color: #fef2f2;
            color: #b91c1c;
        }
        .menu-header {
            padding: 12px 16px;
            font-size: 12px;
            text-transform: uppercase;
            color: #6b7280;
            font-weight: 600;
            letter-spacing: 0.05em;
            background: #f9fafb;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .menu-header span {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        /* Dot styles are defined near the top of this file. */
        .toolbar-alert-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            opacity: 0;
            transition: opacity 0.2s ease;
        }
        .toolbar-alert-overlay.show {
            opacity: 1;
        }
        .toolbar-alert-box {
            background: #fff;
            border-radius: 8px;
            padding: 24px;
            width: 320px;
            max-width: 90vw;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            transform: scale(0.95) translateY(10px);
            transition: transform 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            text-align: center;
            box-sizing: border-box;
        }
        .toolbar-alert-overlay.show .toolbar-alert-box {
            transform: scale(1) translateY(0);
        }
        .toolbar-alert-title {
            font-size: 18px;
            font-weight: 600;
            color: #111827;
            margin: 0 0 8px 0;
        }
        .toolbar-alert-message {
            font-size: 14px;
            color: #4b5563;
            margin: 0 0 24px 0;
            line-height: 1.5;
        }
        .toolbar-alert-actions {
            display: flex;
            gap: 12px;
            justify-content: center;
        }
        .toolbar-alert-btn {
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
            flex: 1;
            font-family: inherit;
        }
        .toolbar-alert-btn-cancel {
            background: #f3f4f6;
            color: #4b5563;
        }
        .toolbar-alert-btn-cancel:hover {
            background: #e5e7eb;
            color: #111827;
        }
        .toolbar-alert-btn-confirm {
            background: #ef4444;
            color: #fff;
        }
        .toolbar-alert-btn-confirm:hover {
            background: #dc2626;
        }
    ` + "`" + `;

	function label(key, fallback) {
	    return typeof toolbarLabels[key] === 'string' && toolbarLabels[key] ? toolbarLabels[key] : fallback;
	}
	var html = ` + "`" + `
	    <div id="wrapper" style="position: relative;">
	        <div id="menu">
	            <div class="menu-header">
	                <span><i class="dot"></i> Go Reauth Proxy</span>
	            </div>
	            <div class="menu-scroll"></div>
	            <div class="menu-divider"></div>
	            ${toolbarData.show_wol ? '<a href="/__wol__" class="menu-item wol-btn"><span class="wol-menu-label"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 10 3-3 3 3"></path><path d="M12 13V7"></path><rect width="20" height="14" x="2" y="3" rx="2"></rect><path d="M12 17v4"></path><path d="M8 21h8"></path></svg>'+label('wol', 'Wake-on-LAN')+'</span></a>' : ''}
	            <a href="/__auth__/api/auth/logout" class="menu-item logout-btn">${label('logout', 'Logout')}</a>
	        </div>
            <div id="fab">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
                    <circle cx="18" cy="6" r="3" fill="#3b82f6" stroke="none" />
                </svg>
            </div>
        </div>
    ` + "`" + `;

    shadow.appendChild(style);
    var div = document.createElement('div');
    div.innerHTML = html;
    shadow.appendChild(div);

	var fab = shadow.getElementById('fab');
	var menu = shadow.getElementById('menu');
	var menuScroll = shadow.querySelector('.menu-scroll');

	function asString(value) {
	    return typeof value === 'string' ? value : '';
	}

	function ensureSlash(path) {
	    path = asString(path);
	    return path.endsWith('/') ? path : path + '/';
	}

	function normalizeHost(host) {
	    return asString(host).trim().toLowerCase().replace(/\.$/, '');
	}

	function isActivePath(rulePath, currentPath) {
	    currentPath = asString(currentPath);
	    if (!currentPath) return false;
	    var rp = asString(rulePath).replace(/\/$/, '');
	    var cp = currentPath.replace(/\/$/, '');
	    return rp === cp || cp.indexOf(rp + '/') === 0 || cp.indexOf(rp) === 0;
	}

	function isActiveHost(ruleHost, currentHost) {
	    var rh = normalizeHost(ruleHost);
	    var ch = normalizeHost(currentHost);
	    return !!rh && rh === ch;
	}

	function appendRightContent(anchor, active) {
	    var right = document.createElement('span');
	    right.className = 'menu-item-right-content';
	    if (active) {
	        var dot = document.createElement('i');
	        dot.className = 'dot';
	        right.appendChild(dot);
	    } else {
	        var go = document.createElement('span');
	        go.className = 'menu-item-go-text';
	        go.textContent = label('go', 'Go');
	        right.appendChild(go);
	    }
	    anchor.appendChild(right);
	}

	function isWebsiteIconPath(value) {
	    return /^\/__assets__\/website_icon\.[A-Za-z0-9][A-Za-z0-9._-]{0,486}$/.test(asString(value).trim());
	}

	function resolveAppIconSrc(value, host) {
	    value = asString(value).trim();
	    if (/^data:image\//i.test(value)) return value;
	    if (!isWebsiteIconPath(value)) return '';
	    try {
	        return new URL(value, buildHostHref(host)).href;
	    } catch (err) {
	        return '';
	    }
	}

	function isAppIconSrc(value) {
	    value = asString(value).trim();
	    if (/^data:image\//i.test(value)) return true;
	    try {
	        var parsed = new URL(value);
	        return (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
	            !parsed.search && !parsed.hash && isWebsiteIconPath(parsed.pathname);
	    } catch (err) {
	        return false;
	    }
	}

	function createMenuLink(label, href, extraClass, active, icon) {
	    var anchor = document.createElement('a');
	    anchor.href = href;
	    anchor.target = '_blank';
	    anchor.rel = 'noopener noreferrer';
	    anchor.className = 'menu-item nav-link ' + extraClass + (active ? ' active' : '');

	    if (isAppIconSrc(icon)) {
	        var image = document.createElement('img');
	        image.className = 'menu-item-icon';
	        image.src = asString(icon).trim();
	        image.alt = '';
	        image.loading = 'lazy';
	        anchor.appendChild(image);
	    }

	    var text = document.createElement('span');
	    text.className = 'menu-item-path';
	    text.textContent = label;
	    anchor.appendChild(text);
	    appendRightContent(anchor, active);
	    return anchor;
	}

	function appendEmptyMenu() {
	    var empty = document.createElement('div');
	    empty.className = 'menu-empty';
	    empty.textContent = label('noRoutesConfigured', 'No routes configured');
	    menuScroll.appendChild(empty);
	}

	function readGroupCollapseState() {
	    var raw = safeGetStoredItem(groupCollapseStorageKey);
	    if (!raw) return {};
	    try {
	        var value = JSON.parse(raw);
	        return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
	    } catch (err) {
	        return {};
	    }
	}

	function createGroupChevronIcon() {
	    var svgNamespace = 'http://www.w3.org/2000/svg';
	    var icon = document.createElementNS(svgNamespace, 'svg');
	    icon.setAttribute('class', 'menu-group-chevron');
	    icon.setAttribute('viewBox', '0 0 16 16');
	    icon.setAttribute('aria-hidden', 'true');
	    icon.setAttribute('focusable', 'false');
	    var path = document.createElementNS(svgNamespace, 'path');
	    path.setAttribute('d', 'M5.75 3.5L10.25 8L5.75 12.5');
	    path.setAttribute('fill', 'none');
	    path.setAttribute('stroke', 'currentColor');
	    path.setAttribute('stroke-width', '1.75');
	    path.setAttribute('stroke-linecap', 'round');
	    path.setAttribute('stroke-linejoin', 'round');
	    icon.appendChild(path);
	    return icon;
	}

	function appendGroupedHostRules(hostRules) {
	    var grouped = [];
	    var indexes = {};
	    var ungrouped = [];
	    var hasEffectiveGroup = false;
	    for (var i = 0; i < hostRules.length; i++) {
	        var rule = hostRules[i] || {};
	        var groupId = asString(rule.group_id).trim();
	        var groupName = asString(rule.group_name).trim();
	        if (!groupId || !groupName) {
	            ungrouped.push(rule);
	            continue;
	        }
	        hasEffectiveGroup = true;
	        if (indexes[groupId] === undefined) {
	            indexes[groupId] = grouped.length;
	            grouped.push({id: groupId, name: groupName, rules: []});
	        }
	        grouped[indexes[groupId]].rules.push(rule);
	    }
	    if (!hasEffectiveGroup) return false;
	    if (ungrouped.length > 0) {
	        grouped.push({
	            id: '__ungrouped__',
	            name: label('ungrouped', 'Ungrouped'),
	            rules: ungrouped
	        });
	    }

	    var collapseState = readGroupCollapseState();
	    for (var groupIndex = 0; groupIndex < grouped.length; groupIndex++) {
	        var group = grouped[groupIndex];
	        var active = false;
	        for (var activeIndex = 0; activeIndex < group.rules.length; activeIndex++) {
	            if (isActiveHost(group.rules[activeIndex].host, toolbarData.current_host)) {
	                active = true;
	                break;
	            }
	        }
	        var hasSavedPreference = typeof collapseState[group.id] === 'boolean';
	        var collapsed = hasSavedPreference ? collapseState[group.id] : !active;
	        var section = document.createElement('div');
	        section.className = 'menu-group' + (collapsed ? ' collapsed' : '');
	        var header = document.createElement('button');
	        header.type = 'button';
	        header.className = 'menu-group-header';
	        header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
	        var chevron = createGroupChevronIcon();
	        var title = document.createElement('span');
	        title.className = 'menu-group-title';
	        title.textContent = group.name;
	        var count = document.createElement('span');
	        count.className = 'menu-group-count';
	        count.textContent = String(group.rules.length);
	        header.appendChild(chevron);
	        header.appendChild(title);
	        header.appendChild(count);
	        var items = document.createElement('div');
	        items.className = 'menu-group-items';
	        items.id = 'menu-group-items-' + groupIndex;
	        items.setAttribute('aria-hidden', collapsed ? 'true' : 'false');
	        if (collapsed) items.setAttribute('inert', '');
	        header.setAttribute('aria-controls', items.id);
	        var itemsInner = document.createElement('div');
	        itemsInner.className = 'menu-group-items-inner';
	        for (var itemIndex = 0; itemIndex < group.rules.length; itemIndex++) {
	            var item = group.rules[itemIndex];
	            var host = asString(item.host);
	            var itemLabel = asString(item.label) || host;
	            var icon = toolbarData.show_app_icon ? resolveAppIconSrc(item.favicon, host) : '';
	            var link = createMenuLink(itemLabel, '/', 'host-link', isActiveHost(host, toolbarData.current_host), icon);
	            link.setAttribute('data-host', host);
	            itemsInner.appendChild(link);
	        }
	        items.appendChild(itemsInner);
	        header.addEventListener('click', (function(groupID, node, button, content) {
	            return function() {
	                var nextCollapsed = !node.classList.contains('collapsed');
	                node.classList.toggle('collapsed', nextCollapsed);
	                button.setAttribute('aria-expanded', nextCollapsed ? 'false' : 'true');
	                content.setAttribute('aria-hidden', nextCollapsed ? 'true' : 'false');
	                if (nextCollapsed) content.setAttribute('inert', '');
	                else content.removeAttribute('inert');
	                collapseState[groupID] = nextCollapsed;
	                safeSetStoredItem(groupCollapseStorageKey, JSON.stringify(collapseState));
	            };
	        })(group.id, section, header, items));
	        section.appendChild(header);
	        section.appendChild(items);
	        menuScroll.appendChild(section);
	    }
	    return true;
	}

	function populateMenu() {
	    if (!menuScroll) return;
	    var hostRules = Array.isArray(toolbarData.host_rules) ? toolbarData.host_rules : [];
	    var rules = Array.isArray(toolbarData.rules) ? toolbarData.rules : [];

	    if (hostRules.length > 0) {
	        if (appendGroupedHostRules(hostRules)) {
	            return;
	        }
	        for (var i = 0; i < hostRules.length; i++) {
	            var host = asString(hostRules[i].host);
	            var label = asString(hostRules[i].label) || host;
	            var icon = toolbarData.show_app_icon ? resolveAppIconSrc(hostRules[i].favicon, host) : '';
	            var hostLink = createMenuLink(label, '/', 'host-link', isActiveHost(host, toolbarData.current_host), icon);
	            hostLink.setAttribute('data-host', host);
	            menuScroll.appendChild(hostLink);
	        }
	        return;
	    }

	    if (rules.length > 0) {
	        for (var j = 0; j < rules.length; j++) {
	            var path = asString(rules[j].path);
	            menuScroll.appendChild(createMenuLink(path, ensureSlash(path), 'rule-link', isActivePath(path, toolbarData.current_path), ''));
	        }
	        return;
	    }

	    appendEmptyMenu();
	}

	populateMenu();

	function buildHostHref(host) {
	    host = asString(host).trim();
	    if (!host) return '/';
	    var port = window.location.port ? ':' + window.location.port : '';
	    var candidate = window.location.protocol + '//' + host + port + '/';
	    try {
	        return new URL(candidate).href;
	    } catch (err) {
	        return '/';
	    }
	}

	var toolbarWarmupStorageKey = 'reauth_proxy_toolbar_warmup';
	var toolbarWarmupHistoryLimit = 32;
	var toolbarWarmupPreconnectLimit = 2;
	var toolbarWarmupWeekMillis = 7 * 24 * 60 * 60 * 1000;
	var toolbarWarmupOrigins = {};

	function toolbarWarmupOrigin(href) {
	    try {
	        var target = new URL(href, window.location.href);
	        if ((target.protocol !== 'http:' && target.protocol !== 'https:') || target.origin === window.location.origin) {
	            return '';
	        }
	        return target.origin;
	    } catch (err) {
	        return '';
	    }
	}

	function readToolbarWarmupHistory() {
	    var raw = safeGetStoredItem(toolbarWarmupStorageKey);
	    if (!raw) return {};
	    try {
	        var parsed = JSON.parse(raw);
	        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
	    } catch (err) {
	        return {};
	    }
	}

	function writeToolbarWarmupHistory(history) {
	    var entries = [];
	    for (var origin in history) {
	        if (!Object.prototype.hasOwnProperty.call(history, origin)) continue;
	        var entry = history[origin] || {};
	        var clicks = Number(entry.clicks);
	        var last = Number(entry.last);
	        if (!isFinite(clicks) || clicks < 1 || !isFinite(last) || last < 0) continue;
	        entries.push({origin: origin, clicks: Math.floor(clicks), last: Math.floor(last)});
	    }
	    entries.sort(function(left, right) {
	        return right.last - left.last || right.clicks - left.clicks || (left.origin < right.origin ? -1 : 1);
	    });
	    var bounded = {};
	    for (var i = 0; i < entries.length && i < toolbarWarmupHistoryLimit; i++) {
	        bounded[entries[i].origin] = {clicks: entries[i].clicks, last: entries[i].last};
	    }
	    safeSetStoredItem(toolbarWarmupStorageKey, JSON.stringify(bounded));
	    return bounded;
	}

	function rememberToolbarWarmupOrigin(origin) {
	    if (!origin) return;
	    var history = readToolbarWarmupHistory();
	    var previous = history[origin] || {};
	    var clicks = Number(previous.clicks);
	    history[origin] = {
	        clicks: isFinite(clicks) && clicks > 0 ? Math.floor(clicks) + 1 : 1,
	        last: Date.now()
	    };
	    writeToolbarWarmupHistory(history);
	}

	function preconnectToolbarOrigin(origin) {
	    if (!origin || toolbarWarmupOrigins[origin]) return;
	    toolbarWarmupOrigins[origin] = true;
	    var hint = document.createElement('link');
	    hint.rel = 'preconnect';
	    hint.href = origin;
	    hint.crossOrigin = 'anonymous';
	    var parent = document.head || document.getElementsByTagName('head')[0] || document.documentElement;
	    if (parent) parent.appendChild(hint);
	}

	function warmToolbarLink(link) {
	    if (!link) return;
	    preconnectToolbarOrigin(toolbarWarmupOrigin(link.href || link.getAttribute('href')));
	}

	function attachToolbarWarmup(link) {
	    if (!link) return;
	    var warm = function() { warmToolbarLink(link); };
	    link.addEventListener('pointerenter', warm);
	    link.addEventListener('focus', warm);
	    link.addEventListener('touchstart', warm, {passive: true});
	    link.addEventListener('click', function() {
	        var origin = toolbarWarmupOrigin(link.href || link.getAttribute('href'));
	        rememberToolbarWarmupOrigin(origin);
	        preconnectToolbarOrigin(origin);
	    });
	}

	function shouldSkipToolbarIdleWarmup() {
	    if (document.visibilityState && document.visibilityState !== 'visible') return true;
	    var connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
	    if (!connection) return false;
	    return connection.saveData || connection.effectiveType === 'slow-2g' || connection.effectiveType === '2g';
	}

	function scheduleToolbarIdleWarmup() {
	    if (shouldSkipToolbarIdleWarmup()) return;
	    var run = function() {
	        if (shouldSkipToolbarIdleWarmup()) return;
	        var hostRules = Array.isArray(toolbarData.host_rules) ? toolbarData.host_rules : [];
	        var history = readToolbarWarmupHistory();
	        var candidates = [];
	        var seen = {};
	        var now = Date.now();
	        for (var i = 0; i < hostRules.length; i++) {
	            var origin = toolbarWarmupOrigin(buildHostHref(asString((hostRules[i] || {}).host)));
	            if (!origin || seen[origin]) continue;
	            seen[origin] = true;
	            var entry = history[origin] || {};
	            var clicks = Number(entry.clicks);
	            var last = Number(entry.last);
	            var age = isFinite(last) ? Math.max(0, now - last) : toolbarWarmupWeekMillis;
	            var recency = Math.max(0, 1 - age / toolbarWarmupWeekMillis);
	            var score = (isFinite(clicks) && clicks > 0 ? 4 * Math.log(1 + clicks) : 0) + 6 * recency;
	            candidates.push({origin: origin, score: score, index: i});
	        }
	        candidates.sort(function(left, right) {
	            return right.score - left.score || left.index - right.index;
	        });
	        for (var j = 0; j < candidates.length && j < toolbarWarmupPreconnectLimit; j++) {
	            preconnectToolbarOrigin(candidates[j].origin);
	        }
	    };
	    var afterLoad = function() {
	        if (window.requestIdleCallback) window.requestIdleCallback(run, {timeout: 1500});
	        else window.setTimeout(run, 250);
	    };
	    if (document.readyState === 'complete') afterLoad();
	    else window.addEventListener('load', afterLoad, {once: true});
	}

    var navLinks = shadow.querySelectorAll('.nav-link');
    for (var i = 0; i < navLinks.length; i++) {
        var host = navLinks[i].getAttribute('data-host');
        if (host) {
            navLinks[i].setAttribute('href', buildHostHref(host));
            attachToolbarWarmup(navLinks[i]);
        }

        navLinks[i].addEventListener('click', function(e) {
            e.preventDefault(); 
            e.stopPropagation(); 
            window.open(this.getAttribute('href'), '_blank', 'noopener,noreferrer');
            menu.classList.remove('open');
        });
    }

    scheduleToolbarIdleWarmup();

    var isDragging = false;
    var startX, startY, initialLeft, initialTop;
    var dragged = false;
    var lastTouchTime = 0;

    fab.addEventListener('mousedown', onDragStart);
    fab.addEventListener('touchstart', onDragStart, { passive: false });

    function onDragStart(e) {
        if (e.type === 'touchstart') {
            lastTouchTime = Date.now();
        } else if (e.type === 'mousedown') {
            if (Date.now() - lastTouchTime < 500) return;
            if (e.button !== 0) return;
        }
        
        var clientX = e.type === 'touchstart' ? e.touches[0].clientX : e.clientX;
        var clientY = e.type === 'touchstart' ? e.touches[0].clientY : e.clientY;
        
        isDragging = true;
        dragged = false;
        startX = clientX;
        startY = clientY;
        
        var rect = container.getBoundingClientRect();
        
        container.style.bottom = 'auto';
        container.style.right = 'auto';
        container.style.left = rect.left + 'px';
        container.style.top = rect.top + 'px';
        
        initialLeft = rect.left;
        initialTop = rect.top;
        
        if (e.type === 'mousedown') {
            document.addEventListener('mousemove', onDragMove);
            document.addEventListener('mouseup', onDragEnd);
            e.preventDefault();
        } else {
            document.addEventListener('touchmove', onDragMove, { passive: false });
            document.addEventListener('touchend', onDragEnd);
            document.addEventListener('touchcancel', onDragEnd);
        }
    }

    function onDragMove(e) {
        if (!isDragging) return;
        
        var clientX = e.type === 'touchmove' ? e.touches[0].clientX : e.clientX;
        var clientY = e.type === 'touchmove' ? e.touches[0].clientY : e.clientY;
        
        var dx = clientX - startX;
        var dy = clientY - startY;
        
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
            dragged = true;
        }
        
        var newLeft = initialLeft + dx;
        var newTop = initialTop + dy;

        if (iconDragMode === 'free') {
            var clamped = clampToolbarPosition(newLeft, newTop);
            newLeft = clamped.left;
            newTop = clamped.top;
        }

        container.style.left = newLeft + 'px';
        container.style.top = newTop + 'px';
        
        if (e.type === 'touchmove' && dragged) {
            e.preventDefault(); // prevent scrolling
        }
    }

    function onDragEnd(e) {
        if (!isDragging) return;
        isDragging = false;
        
        if (e.type === 'mouseup') {
            document.removeEventListener('mousemove', onDragMove);
            document.removeEventListener('mouseup', onDragEnd);
        } else {
            document.removeEventListener('touchmove', onDragMove);
            document.removeEventListener('touchend', onDragEnd);
            document.removeEventListener('touchcancel', onDragEnd);
        }
        
        if (e.type === 'touchend' && e.cancelable) {
            e.preventDefault();
        }
        
        if (dragged) {
            if (iconDragMode === 'free') {
                saveFreePosition();
            } else {
                snapToEdge();
            }
        } else {
            // Because toggleMenu might cause reflows, defer it slightly
            setTimeout(toggleMenu, 10);
        }
    }

    function saveFreePosition() {
        var rect = container.getBoundingClientRect();
        writeFreePosition(rect.left, rect.top);
        updateMenuPosition();
    }
    
    function snapToEdge() {
        var rect = container.getBoundingClientRect();
        var vv = window.visualViewport;
        var vvLeft = vv ? vv.offsetLeft : 0;
        var vvTop = vv ? vv.offsetTop : 0;
        var vvWidth = vv ? vv.width : window.innerWidth;
        var vvHeight = vv ? vv.height : window.innerHeight;
        
        var centerX = rect.left + rect.width / 2;
        var centerY = rect.top + rect.height / 2;
        
        var isLeft = centerX < (vvLeft + vvWidth / 2);
        var isTop = centerY < (vvTop + vvHeight / 2);
        
        container.style.transition = 'left 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), top 0.3s cubic-bezier(0.2, 0.8, 0.2, 1)';
        
        var pos = '';
        if (isTop && isLeft) pos = 'tl';
        else if (isTop && !isLeft) pos = 'tr';
        else if (!isTop && isLeft) pos = 'bl';
        else pos = 'br';
        
        safeSetStoredItem(cornerPositionStorageKey, pos);
        
        applyCornerPosition(pos);
        
        setTimeout(() => {
            container.style.transition = '';
        }, 300);
        
        updateMenuPosition();
    }

    function toggleMenu() {
        if (menu.classList.contains('open')) {
            menu.classList.remove('open');
        } else {
            updateMenuPosition();
            if (menuScroll) {
                menuScroll.scrollTop = 0;
            }
            menu.classList.add('open');
        }
    }
    
    function updateMenuPosition() {
        var rect = container.getBoundingClientRect();
        var vv = window.visualViewport;
        var vvLeft = vv ? vv.offsetLeft : 0;
        var vvTop = vv ? vv.offsetTop : 0;
        var vvWidth = vv ? vv.width : window.innerWidth;
        var vvHeight = vv ? vv.height : window.innerHeight;
        
        var centerX = rect.left + rect.width / 2;
        var centerY = rect.top + rect.height / 2;
        
        var isLeft = centerX < (vvLeft + vvWidth / 2);
        var isTop = centerY < (vvTop + vvHeight / 2);
        
        if (isLeft) {
            menu.style.right = 'auto';
            menu.style.left = '0';
            menu.style.transformOrigin = isTop ? 'top left' : 'bottom left';
        } else {
            menu.style.left = 'auto';
            menu.style.right = '0';
            menu.style.transformOrigin = isTop ? 'top right' : 'bottom right';
        }
        
        if (!isTop) {
            menu.style.bottom = '56px';
            menu.style.top = 'auto';
        } else {
            menu.style.top = '56px';
            menu.style.bottom = 'auto';
        }

        var viewportPadding = 20;
        var menuOffset = 56;
        var menuBottomAnchor = rect.top + rect.height - menuOffset;
        var menuTopAnchor = rect.top + menuOffset;
        var availableHeight = isTop ?
            (vvTop + vvHeight - viewportPadding) - menuTopAnchor :
            menuBottomAnchor - (vvTop + viewportPadding);

        var constrainedHeight = Math.max(0, Math.floor(availableHeight));
        menu.style.maxHeight = constrainedHeight + 'px';
    }

    var logoutBtn = shadow.querySelector('.logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation(); 
            var href = this.getAttribute('href');
            
            var overlay = document.createElement('div');
            overlay.className = 'toolbar-alert-overlay';
            
            var box = document.createElement('div');
            box.className = 'toolbar-alert-box';
            
            var titleHtml = '<h3 class="toolbar-alert-title">' + label('logoutTitle', 'Logout') + '</h3>';
            var msgHtml = '<p class="toolbar-alert-message">' + label('logoutMessage', 'Are you sure you want to logout?') + '</p>';
            var actionsHtml = '<div class="toolbar-alert-actions">' +
                '<button class="toolbar-alert-btn toolbar-alert-btn-cancel">' + label('cancel', 'Cancel') + '</button>' +
                '<button class="toolbar-alert-btn toolbar-alert-btn-confirm">' + label('confirm', 'Confirm') + '</button>' +
                '</div>';
                
            box.innerHTML = titleHtml + msgHtml + actionsHtml;
            overlay.appendChild(box);
            
            var cancelBtn = box.querySelector('.toolbar-alert-btn-cancel');
            var confirmBtn = box.querySelector('.toolbar-alert-btn-confirm');
            
            function updateOverlayPos() {
                var vv = window.visualViewport;
                if (vv) {
                    overlay.style.top = vv.offsetTop + 'px';
                    overlay.style.left = vv.offsetLeft + 'px';
                    overlay.style.width = vv.width + 'px';
                    overlay.style.height = vv.height + 'px';
                    overlay.style.bottom = 'auto';
                    overlay.style.right = 'auto';
                }
            }
            updateOverlayPos();
            
            if (window.visualViewport) {
                window.visualViewport.addEventListener('resize', updateOverlayPos);
                window.visualViewport.addEventListener('scroll', updateOverlayPos);
            }
            window.addEventListener('resize', updateOverlayPos);
            window.addEventListener('scroll', updateOverlayPos);
            
            function close() {
                overlay.classList.remove('show');
                menu.classList.remove('open');
                if (window.visualViewport) {
                    window.visualViewport.removeEventListener('resize', updateOverlayPos);
                    window.visualViewport.removeEventListener('scroll', updateOverlayPos);
                }
                window.removeEventListener('resize', updateOverlayPos);
                window.removeEventListener('scroll', updateOverlayPos);
                setTimeout(function() {
                    if (overlay.parentNode) {
                        overlay.parentNode.removeChild(overlay);
                    }
                }, 200);
            }
            
            cancelBtn.addEventListener('click', close);
            confirmBtn.addEventListener('click', function() {
                close();
                window.location.href = href;
            });
            
            overlay.addEventListener('click', function(evt) {
                if (evt.target === overlay) {
                    close();
                }
            });
            
            shadow.appendChild(overlay);
            
            // Trigger reflow for animation
            overlay.offsetHeight;
            overlay.classList.add('show');
        });
    }

    document.addEventListener('click', function(e) {
        if (isDragging || dragged) return;
        var path = e.composedPath ? e.composedPath() : e.path;
        var clickedInside = false;
        if (path) {
            for (var i = 0; i < path.length; i++) {
                if (path[i] === container) {
                    clickedInside = true;
                    break;
                }
            }
        } else {
            clickedInside = container.contains(e.target);
        }
        
        if (!clickedInside && menu.classList.contains('open')) {
            menu.classList.remove('open');
        }
    });

    function updateToolbarPosition() {
        if (isDragging) return;
        applySavedToolbarPosition();
        if (menu.classList.contains('open')) {
            updateMenuPosition();
        }
    }

    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', updateToolbarPosition);
        window.visualViewport.addEventListener('scroll', updateToolbarPosition);
    }
    window.addEventListener('resize', updateToolbarPosition);
    window.addEventListener('scroll', updateToolbarPosition);

    document.body.appendChild(container);
})(window, document);
	</script>
	`

const toolbarDataMarker = "__REAUTH_TOOLBAR_DATA__"

// Keep this decoded-byte limit aligned with MAX_FAVICON_BYTES in the Rust
// control plane. Base64 expands the transport string and must not reduce the
// effective image limit.
const toolbarFaviconMaxDecodedBytes = 128 * 1024
const toolbarRuntimeDataExpression = `(function() {
    var loader = document.getElementById('reauth-proxy-toolbar-loader') ||
        document.getElementById('reauth-proxy-toolbar-v2-loader');
    if (!loader) return {};
    try {
        return JSON.parse(loader.getAttribute('data-toolbar') || '{}');
    } catch (err) {
        return {};
    }
})()`

var (
	toolbarTemplatePrefix   string
	toolbarTemplateSuffix   string
	toolbarRuntime          []byte
	toolbarAssetPath        string
	toolbarV2TemplatePrefix string
	toolbarV2TemplateSuffix string
	toolbarV2Runtime        []byte
	toolbarV2AssetPath      string
)

func init() {
	runtimePrefix, runtimeSuffix, found := strings.Cut(toolbarTemplate, toolbarDataMarker)
	if !found {
		panic("toolbar runtime data marker is missing")
	}

	runtimeDocument := strings.TrimSpace(runtimePrefix + toolbarRuntimeDataExpression + runtimeSuffix)
	runtimeDocument = strings.TrimSpace(strings.TrimPrefix(runtimeDocument, "<script>"))
	runtimeDocument = strings.TrimSpace(strings.TrimSuffix(runtimeDocument, "</script>"))
	toolbarRuntime = []byte(runtimeDocument)

	digest := sha256.Sum256(toolbarRuntime)
	toolbarAssetPath = "/__assets__/toolbar/toolbar." + hex.EncodeToString(digest[:]) + ".js"
	toolbarTemplatePrefix = `<script id="reauth-proxy-toolbar-loader" src="` + toolbarAssetPath + `" data-toolbar='`
	toolbarTemplateSuffix = `' defer></script>`
	initToolbarV2Runtime()
	initToolbarBootstrap()
}

type toolbarLabels struct {
	WOL                string `json:"wol"`
	Logout             string `json:"logout"`
	LogoutTitle        string `json:"logoutTitle"`
	LogoutMessage      string `json:"logoutMessage"`
	Cancel             string `json:"cancel"`
	Confirm            string `json:"confirm"`
	Go                 string `json:"go"`
	NoRoutesConfigured string `json:"noRoutesConfigured"`
	Ungrouped          string `json:"ungrouped"`
	Applications       string `json:"applications"`
	All                string `json:"all"`
	MoreActions        string `json:"moreActions"`
	Close              string `json:"close"`
	Current            string `json:"current"`
}

func ShouldSuppressToolbarForUserAgent(userAgent string) bool {
	normalized := strings.TrimSpace(userAgent)
	if normalized == "" {
		return false
	}

	return containsFoldASCIIString(normalized, "com.trim.app") ||
		containsFoldASCIIString(normalized, "com.trim.media") ||
		containsFoldASCIIString(normalized, "fnos")
}

func GenerateToolbar(rules []models.Rule, currentPath string) string {
	return GenerateToolbarForLocale(i18n.DefaultLocaleValue(), rules, currentPath)
}

func GenerateToolbarForRequest(r *http.Request, rules []models.Rule, currentPath string) string {
	return GenerateToolbarForLocale(i18n.ResolveRequestLocale(r), rules, currentPath)
}

func GenerateToolbarForLocale(locale string, rules []models.Rule, currentPath string) string {
	return GenerateToolbarWithHostsForLocale(locale, rules, nil, currentPath, "", "", models.GatewayPortalConfig{})
}

func GatewayPortalHostLabel(rule models.HostRule, portalConfig models.GatewayPortalConfig) string {
	return gatewayPortalHostLabel(rule, models.NormalizeGatewayPortalConfig(portalConfig))
}

func gatewayPortalHostLabel(rule models.HostRule, normalizedPortal models.GatewayPortalConfig) string {
	if normalizedPortal.DisplayStyle == models.GatewayPortalDisplayStyleTitle {
		if title := strings.TrimSpace(rule.Title); title != "" {
			return title
		}
	}
	return rule.Host
}

func GatewayPortalHostFavicon(rule models.HostRule, portalConfig models.GatewayPortalConfig) string {
	return gatewayPortalHostFavicon(rule, models.NormalizeGatewayPortalConfig(portalConfig))
}

func gatewayPortalHostFavicon(rule models.HostRule, normalizedPortal models.GatewayPortalConfig) string {
	if !normalizedPortal.ShowAppIcon {
		return ""
	}
	if configuredPath := EffectiveWebsiteIconPath(rule.WebsiteIconPath, ""); configuredPath != "" {
		return configuredPath
	}
	favicon := strings.TrimSpace(rule.Favicon)
	if _, _, ok := validateBase64ImageDataURL(favicon, toolbarFaviconMaxDecodedBytes); !ok {
		return ""
	}
	return EffectiveWebsiteIconPath("", favicon)
}

func gatewayPortalHostInlineFavicon(rule models.HostRule, normalizedPortal models.GatewayPortalConfig) string {
	if !normalizedPortal.ShowAppIcon {
		return ""
	}
	favicon := strings.TrimSpace(rule.Favicon)
	if _, _, ok := validateBase64ImageDataURL(favicon, toolbarFaviconMaxDecodedBytes); !ok {
		return ""
	}
	return favicon
}

func normalizeToolbarHost(host string) string {
	value := strings.TrimSpace(host)
	value = strings.TrimSuffix(value, ".")
	return lowerASCIIString(value)
}

func toolbarHostMatchesNormalized(host string, normalized string) bool {
	value := strings.TrimSpace(host)
	value = strings.TrimSuffix(value, ".")
	if len(value) != len(normalized) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 || normalized[i] >= 0x80 {
			return strings.ToLower(value) == normalized
		}
		if lowerASCIIByte(value[i]) != normalized[i] {
			return false
		}
	}
	return true
}

func isToolbarNavigableTarget(rawTarget string) bool {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return true
	}

	scheme, rest, ok := strings.Cut(target, "://")
	if !ok {
		return false
	}
	if !equalFoldASCIIString(scheme, "http") && !equalFoldASCIIString(scheme, "https") {
		return false
	}

	host := rest
	if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
		host = host[:idx]
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n") {
		return false
	}
	if strings.HasPrefix(host, "[") {
		return strings.IndexByte(host, ']') > 1
	}
	if strings.HasPrefix(host, ":") {
		return false
	}
	if strings.Contains(host, "[") || strings.Contains(host, "]") {
		return false
	}
	return true
}

func filterToolbarRules(rules []models.Rule) []models.Rule {
	for i, rule := range rules {
		if isToolbarNavigableTarget(rule.Target) {
			continue
		}
		filtered := make([]models.Rule, 0, len(rules)-1)
		filtered = append(filtered, rules[:i]...)
		for _, candidate := range rules[i+1:] {
			if isToolbarNavigableTarget(candidate.Target) {
				filtered = append(filtered, candidate)
			}
		}
		return filtered
	}
	return rules
}

func filterToolbarHostRules(hostRules []models.HostRule, excludedHost string) []models.HostRule {
	normalizedExcludedHost := normalizeToolbarHost(excludedHost)
	for i, rule := range hostRules {
		excluded := normalizedExcludedHost != "" && toolbarHostMatchesNormalized(rule.Host, normalizedExcludedHost)
		if !excluded && isToolbarNavigableTarget(rule.Target) {
			continue
		}
		filtered := make([]models.HostRule, 0, len(hostRules)-1)
		filtered = append(filtered, hostRules[:i]...)
		for _, candidate := range hostRules[i+1:] {
			if normalizedExcludedHost != "" && toolbarHostMatchesNormalized(candidate.Host, normalizedExcludedHost) {
				continue
			}
			if !isToolbarNavigableTarget(candidate.Target) {
				continue
			}
			filtered = append(filtered, candidate)
		}
		return filtered
	}
	return hostRules
}

func filterToolbarHostRulesByHost(hostRules []models.HostRule, excludedHost string) []models.HostRule {
	normalizedExcludedHost := normalizeToolbarHost(excludedHost)
	if normalizedExcludedHost == "" {
		return hostRules
	}

	for i, rule := range hostRules {
		if toolbarHostMatchesNormalized(rule.Host, normalizedExcludedHost) {
			filtered := make([]models.HostRule, 0, len(hostRules)-1)
			filtered = append(filtered, hostRules[:i]...)
			filtered = append(filtered, hostRules[i+1:]...)
			return filtered
		}
	}
	return hostRules
}

func GenerateToolbarWithHosts(rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	return GenerateToolbarWithHostsForLocale(i18n.DefaultLocaleValue(), rules, hostRules, currentPath, currentHost, excludedHost, portalConfig)
}

func GenerateToolbarWithHostsForRequest(r *http.Request, rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	return GenerateToolbarWithHostsForLocale(i18n.ResolveRequestLocale(r), rules, hostRules, currentPath, currentHost, excludedHost, portalConfig)
}

func GenerateToolbarWithHostsForLocale(locale string, rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	filteredRules := filterToolbarRules(rules)
	filteredHostRules := filterToolbarHostRules(hostRules, excludedHost)
	return GenerateToolbarWithPrefilteredHostsForLocale(locale, filteredRules, filteredHostRules, currentPath, currentHost, "", portalConfig)
}

func GenerateToolbarWithPrefilteredHostsForRequest(r *http.Request, filteredRules []models.Rule, filteredHostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	return GenerateToolbarWithPrefilteredHostsForLocale(i18n.ResolveRequestLocale(r), filteredRules, filteredHostRules, currentPath, currentHost, excludedHost, portalConfig)
}

func GenerateToolbarWithPrefilteredHostsForLocale(locale string, filteredRules []models.Rule, filteredHostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	normalizedPortal := models.NormalizeGatewayPortalConfig(portalConfig)
	if !normalizedPortal.Enabled {
		return ""
	}
	normalizedExcludedHost := normalizeToolbarHost(excludedHost)
	labels := resolveToolbarLabels(locale)
	return renderToolbarTemplateData(filteredRules, filteredHostRules, currentPath, currentHost, normalizedExcludedHost, normalizedPortal, labels)
}

// GenerateToolbarDataWithPrefilteredHostsForRequest serializes the fresh
// toolbar data endpoint response. The payload retains the runtime's existing
// data shape and adds only the selected content-addressed runtime URL.
func GenerateToolbarDataWithPrefilteredHostsForRequest(r *http.Request, filteredRules []models.Rule, filteredHostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	return GenerateToolbarDataWithPrefilteredHostsForLocale(i18n.ResolveRequestLocale(r), filteredRules, filteredHostRules, currentPath, currentHost, excludedHost, portalConfig)
}

// GenerateToolbarDataWithPrefilteredHostsForLocale is the locale-explicit
// variant used by tests and non-request callers.
func GenerateToolbarDataWithPrefilteredHostsForLocale(locale string, filteredRules []models.Rule, filteredHostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	normalizedPortal := models.NormalizeGatewayPortalConfig(portalConfig)
	if !normalizedPortal.Enabled {
		return ""
	}

	normalizedExcludedHost := normalizeToolbarHost(excludedHost)
	labels := resolveToolbarLabels(locale)
	payloadSize := estimateToolbarPayloadSize(filteredRules, filteredHostRules, currentPath, currentHost, normalizedExcludedHost, normalizedPortal, labels)
	var b strings.Builder
	b.Grow(payloadSize + 128)
	b.WriteString(`{"runtime_url":`)
	writeJSONString(&b, ToolbarAssetPathForVersion(normalizedPortal.Version))
	b.WriteString(`,"data":`)
	writeToolbarPayloadJSON(&b, filteredRules, filteredHostRules, currentPath, currentHost, normalizedExcludedHost, normalizedPortal, labels)
	b.WriteByte('}')
	return b.String()
}

func resolveToolbarLabels(locale string) toolbarLabels {
	return toolbarLabels{
		WOL:                i18n.T(locale, "gateway.wolShortcut"),
		Logout:             i18n.T(locale, "gateway.logout"),
		LogoutTitle:        i18n.T(locale, "gateway.logoutConfirmTitle"),
		LogoutMessage:      i18n.T(locale, "gateway.logoutConfirmMessage"),
		Cancel:             i18n.T(locale, "gateway.cancel"),
		Confirm:            i18n.T(locale, "gateway.confirm"),
		Go:                 i18n.T(locale, "gateway.go"),
		NoRoutesConfigured: i18n.T(locale, "gateway.noRoutesConfigured"),
		Ungrouped:          i18n.T(locale, "gateway.ungrouped"),
		Applications:       i18n.T(locale, "gateway.applications"),
		All:                i18n.T(locale, "gateway.all"),
		MoreActions:        i18n.T(locale, "gateway.moreActions"),
		Close:              i18n.T(locale, "gateway.close"),
		Current:            i18n.T(locale, "gateway.current"),
	}
}

func renderToolbarTemplateData(rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, normalizedExcludedHost string, portalConfig models.GatewayPortalConfig, labels toolbarLabels) string {
	templatePrefix := toolbarTemplatePrefix
	templateSuffix := toolbarTemplateSuffix
	if portalConfig.Version == models.GatewayPortalVersionV2 {
		templatePrefix = toolbarV2TemplatePrefix
		templateSuffix = toolbarV2TemplateSuffix
	}
	payloadSize := estimateToolbarPayloadSize(rules, hostRules, currentPath, currentHost, normalizedExcludedHost, portalConfig, labels)
	var payload strings.Builder
	payload.Grow(payloadSize)
	writeToolbarPayloadJSON(&payload, rules, hostRules, currentPath, currentHost, normalizedExcludedHost, portalConfig, labels)
	dnsPrefetchLinks := renderToolbarDNSPrefetchLinks(hostRules, normalizedExcludedHost)

	var b strings.Builder
	b.Grow(len(dnsPrefetchLinks) + len(templatePrefix) + payload.Len() + len(templateSuffix))
	b.WriteString(dnsPrefetchLinks)
	b.WriteString(templatePrefix)
	b.WriteString(strings.ReplaceAll(payload.String(), "'", "&#39;"))
	b.WriteString(templateSuffix)
	return b.String()
}

// renderToolbarDNSPrefetchLinks returns static DNS hints for the same host
// rules the toolbar is allowed to display. The toolbar is injected near the
// end of the document, so keeping these links immediately before the runtime
// loader lets the browser start resolving hosts before the deferred script
// executes.
func renderToolbarDNSPrefetchLinks(hostRules []models.HostRule, normalizedExcludedHost string) string {
	if len(hostRules) == 0 {
		return ""
	}

	seen := make(map[string]struct{}, len(hostRules))
	var hints strings.Builder
	for _, rule := range hostRules {
		if normalizedExcludedHost != "" && toolbarHostMatchesNormalized(rule.Host, normalizedExcludedHost) {
			continue
		}
		hostname := toolbarDNSPrefetchHostname(rule.Host)
		if hostname == "" {
			continue
		}
		if _, exists := seen[hostname]; exists {
			continue
		}
		seen[hostname] = struct{}{}
		hints.WriteString(`<link rel="dns-prefetch" href="//`)
		hints.WriteString(html.EscapeString(hostname))
		hints.WriteString(`">`)
	}
	return hints.String()
}

// toolbarDNSPrefetchHostname extracts a DNS hostname from a configured host
// rule. IP literals do not need DNS and malformed or URL-like values must not
// become browser-issued resource hints.
func toolbarDNSPrefetchHostname(host string) string {
	value := normalizeToolbarHost(host)
	if value == "" {
		return ""
	}

	parsed, err := url.Parse("https://" + value)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != value {
		return ""
	}
	hostname := normalizeToolbarHost(parsed.Hostname())
	if hostname == "" {
		return ""
	}
	hostname, err = idna.Lookup.ToASCII(hostname)
	if err != nil {
		return ""
	}
	hostname = lowerASCIIString(hostname)
	if _, err := netip.ParseAddr(hostname); err == nil {
		return ""
	}
	if !isToolbarDNSHostname(hostname) {
		return ""
	}
	return hostname
}

func isToolbarDNSHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			char := label[i]
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func writeToolbarPayloadJSON(b *strings.Builder, rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, normalizedExcludedHost string, portalConfig models.GatewayPortalConfig, labels toolbarLabels) {
	b.WriteString(`{"rules":[`)
	for i, rule := range rules {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"path":`)
		writeJSONString(b, rule.Path)
		b.WriteByte('}')
	}
	b.WriteString(`],"host_rules":[`)
	renderedHostRules := 0
	for _, rule := range hostRules {
		if toolbarHostMatchesExcludedNormalized(rule.Host, normalizedExcludedHost) {
			continue
		}
		if renderedHostRules > 0 {
			b.WriteByte(',')
		}
		label := gatewayPortalHostLabel(rule, portalConfig)
		favicon := gatewayPortalHostFavicon(rule, portalConfig)
		b.WriteString(`{"host":`)
		writeJSONString(b, rule.Host)
		if label != "" {
			b.WriteString(`,"label":`)
			writeJSONString(b, label)
		}
		if favicon != "" {
			b.WriteString(`,"favicon":`)
			writeJSONString(b, favicon)
		}
		if strings.TrimSpace(rule.GroupID) != "" {
			b.WriteString(`,"group_id":`)
			writeJSONString(b, rule.GroupID)
		}
		if strings.TrimSpace(rule.GroupName) != "" {
			b.WriteString(`,"group_name":`)
			writeJSONString(b, rule.GroupName)
		}
		b.WriteByte('}')
		renderedHostRules++
	}
	b.WriteString(`],"current_path":`)
	writeJSONString(b, currentPath)
	b.WriteString(`,"current_host":`)
	writeJSONString(b, currentHost)
	b.WriteString(`,"icon_drag_mode":`)
	writeJSONString(b, portalConfig.IconDragMode)
	if portalConfig.ShowAppIcon {
		b.WriteString(`,"show_app_icon":true`)
	}
	if portalConfig.ShowWOL {
		b.WriteString(`,"show_wol":true`)
	}
	b.WriteString(`,"labels":{"wol":`)
	writeJSONString(b, labels.WOL)
	b.WriteString(`,"logout":`)
	writeJSONString(b, labels.Logout)
	b.WriteString(`,"logoutTitle":`)
	writeJSONString(b, labels.LogoutTitle)
	b.WriteString(`,"logoutMessage":`)
	writeJSONString(b, labels.LogoutMessage)
	b.WriteString(`,"cancel":`)
	writeJSONString(b, labels.Cancel)
	b.WriteString(`,"confirm":`)
	writeJSONString(b, labels.Confirm)
	b.WriteString(`,"go":`)
	writeJSONString(b, labels.Go)
	b.WriteString(`,"noRoutesConfigured":`)
	writeJSONString(b, labels.NoRoutesConfigured)
	b.WriteString(`,"ungrouped":`)
	writeJSONString(b, labels.Ungrouped)
	b.WriteString(`,"applications":`)
	writeJSONString(b, labels.Applications)
	b.WriteString(`,"all":`)
	writeJSONString(b, labels.All)
	b.WriteString(`,"moreActions":`)
	writeJSONString(b, labels.MoreActions)
	b.WriteString(`,"close":`)
	writeJSONString(b, labels.Close)
	b.WriteString(`,"current":`)
	writeJSONString(b, labels.Current)
	b.WriteString(`}}`)
}

func estimateToolbarPayloadSize(rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, normalizedExcludedHost string, portalConfig models.GatewayPortalConfig, labels toolbarLabels) int {
	size := 192 + len(currentPath) + len(currentHost) +
		len(portalConfig.IconDragMode) +
		len(labels.WOL) + len(labels.Logout) + len(labels.LogoutTitle) + len(labels.LogoutMessage) +
		len(labels.Cancel) + len(labels.Confirm) + len(labels.Go) + len(labels.NoRoutesConfigured)
	size += len(labels.Ungrouped) + len(labels.Applications) + len(labels.All) +
		len(labels.MoreActions) + len(labels.Close) + len(labels.Current)
	for _, rule := range rules {
		size += len(rule.Path) + 16
	}
	for _, rule := range hostRules {
		if toolbarHostMatchesExcludedNormalized(rule.Host, normalizedExcludedHost) {
			continue
		}
		size += len(rule.Host) + len(rule.Title) + len(rule.GroupID) + len(rule.GroupName) + len(gatewayPortalHostFavicon(rule, portalConfig)) + 64
	}
	return size
}

func toolbarHostMatchesExcludedNormalized(host string, normalizedExcludedHost string) bool {
	return normalizedExcludedHost != "" && toolbarHostMatchesNormalized(host, normalizedExcludedHost)
}

func writeJSONString(b *strings.Builder, value string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	start := 0
	for i := 0; i < len(value); {
		c := value[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '\\' && c != '"' && c != '<' && c != '>' && c != '&' {
				i++
				continue
			}
			b.WriteString(value[start:i])
			switch c {
			case '\\', '"':
				b.WriteByte('\\')
				b.WriteByte(c)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				b.WriteString(`\u00`)
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString(value[start:i])
			b.WriteString(`\ufffd`)
			i++
			start = i
			continue
		}
		if r == '\u2028' || r == '\u2029' {
			b.WriteString(value[start:i])
			b.WriteString(`\u202`)
			b.WriteByte(hex[r&0xf])
			i += size
			start = i
			continue
		}
		i += size
	}
	b.WriteString(value[start:])
	b.WriteByte('"')
}

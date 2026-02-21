package response

import (
	"bytes"
	"go-reauth-proxy/pkg/models"
	"text/template"
)

const toolbarTemplate = `
<script>
(function(window, document) {
    if (document.getElementById('reauth-proxy-toolbar')) return;

    var container = document.createElement('div');
    container.id = 'reauth-proxy-toolbar';
    container.style.position = 'fixed';
    container.style.zIndex = '2147483647';
    container.style.fontFamily = 'ui-sans-serif, system-ui, sans-serif';

    function applyPosition(pos) {
        var margin = 20;

        container.style.bottom = 'auto';
        container.style.right = 'auto';

        var vv = window.visualViewport;
        var vvLeft = vv ? vv.offsetLeft : 0;
        var vvTop = vv ? vv.offsetTop : 0;
        var vvWidth = vv ? vv.width : window.innerWidth;
        var vvHeight = vv ? vv.height : window.innerHeight;

        var fabSize = 44;

        if (pos === 'tl') {
            container.style.top = (vvTop + margin) + 'px';
            container.style.left = (vvLeft + margin) + 'px';
        } else if (pos === 'tr') {
            container.style.top = (vvTop + margin) + 'px';
            container.style.left = (vvLeft + vvWidth - margin - fabSize) + 'px';
        } else if (pos === 'bl') {
            container.style.top = (vvTop + vvHeight - margin - fabSize) + 'px';
            container.style.left = (vvLeft + margin) + 'px';
        } else {
            container.style.top = (vvTop + vvHeight - margin - fabSize) + 'px';
            container.style.left = (vvLeft + vvWidth - margin - fabSize) + 'px';
        }
    }

    applyPosition(localStorage.getItem('reauth_proxy_toolbar_pos') || 'br');

    var shadow = container.attachShadow({mode: 'open'});

    var style = document.createElement('style');
    style.textContent = ` + "`" + `
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
            color: #4b5563;
            text-decoration: none;
            font-size: 14px;
            border-bottom: 1px solid #f3f4f6;
            transition: background-color 0.15s, color 0.15s;
            display: block;
            text-overflow: ellipsis;
            white-space: nowrap;
            overflow: hidden;
        }
        .menu-item:last-child {
            border-bottom: none;
        }
        .menu-item:hover {
            background-color: #f9fafb;
            color: #111827;
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
        .dot {
            width: 8px;
            height: 8px;
            background-color: #10b981;
            border-radius: 50%;
            display: inline-block;
        }
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

    var html = ` + "`" + `
        <div id="wrapper" style="position: relative;">
            <div id="menu">
                <div class="menu-header">
                    <span><i class="dot"></i> Access Routes</span>
                </div>
                {{range .Rules}}
                <a href="{{.Path}}" class="menu-item">{{.Path}} <span style="float: right; color: #9ca3af; font-size: 12px;">Go</span></a>
                {{end}}
                <div style="height: 4px; background: #f9fafb;"></div>
                <a href="/__auth__/logout" class="menu-item logout-btn">Logout</a>
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
            snapToEdge();
        } else {
            // Because toggleMenu might cause reflows, defer it slightly
            setTimeout(toggleMenu, 10);
        }
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
        
        localStorage.setItem('reauth_proxy_toolbar_pos', pos);
        
        applyPosition(pos);
        
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
    }

    var logoutBtn = shadow.querySelector('.logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            var href = this.getAttribute('href');
            
            var overlay = document.createElement('div');
            overlay.className = 'toolbar-alert-overlay';
            
            var box = document.createElement('div');
            box.className = 'toolbar-alert-box';
            
            var titleHtml = '<h3 class="toolbar-alert-title">Logout</h3>';
            var msgHtml = '<p class="toolbar-alert-message">Are you sure you want to logout?</p>';
            var actionsHtml = '<div class="toolbar-alert-actions">' +
                '<button class="toolbar-alert-btn toolbar-alert-btn-cancel">Cancel</button>' +
                '<button class="toolbar-alert-btn toolbar-alert-btn-confirm">Confirm</button>' +
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
        var pos = localStorage.getItem('reauth_proxy_toolbar_pos') || 'br';
        applyPosition(pos);
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

var toolbarTmpl = template.Must(template.New("toolbar").Parse(toolbarTemplate))

func GenerateToolbar(rules []models.Rule) string {
	var buf bytes.Buffer
	data := struct {
		Rules []models.Rule
	}{
		Rules: rules,
	}
	_ = toolbarTmpl.Execute(&buf, data)
	return buf.String()
}

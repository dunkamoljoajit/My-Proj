// =========================================================
// 1. CONFIG & UTILITIES
// =========================================================
const API_BASE = 'http://localhost:3000'; 

// ฟังก์ชันช่วยดึงข้อมูลผู้ใช้และ Token
// components.js (ฉบับแก้ไข: บังคับแสดงสีโลโก้หัวหน้าพยาบาล)

function getUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

function getProfileImageUrl(path) {
    if (!path) return 'https://placehold.co/100?text=User';
    // ตรวจสอบ path ว่ามี http หรือไม่ ถ้าไม่มีให้เติม path ของ server
    const API_BASE = 'http://localhost:3000'; 
    return path.startsWith('http') ? path : `${API_BASE}/uploads/${path}`;
}

async function logout() {
    const user = getUser(); // 1. ดึงข้อมูลผู้ใช้มาก่อนที่จะลบทิ้ง เพื่อเอา UserID
    const token = localStorage.getItem('authToken');

    if (user && user.UserID) {
        try {
            // 2. ยิง API ไปบอก Server ว่า User คนนี้ Logout แล้ว
            await fetch(`${API_BASE}/logout`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ userId: user.UserID })
            });
        } catch (err) {
            console.error("Logout API Error:", err);
            // ต่อให้ API Error ก็ต้องยอมให้ Logout ได้ เพื่อไม่ให้ user ติดอยู่ในระบบ
        }
    }

    // 3. ลบข้อมูลใน LocalStorage (เหมือนเดิม)
    localStorage.removeItem('token');
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');

    // 4. Redirect ไปหน้า Login
    window.location.href = 'login.html';
}
// --- App Header (เมนูบน - แบบมี Dropdown แจ้งเตือนสวยๆ) ---
class AppHeader extends HTMLElement {
    connectedCallback() {
        const user = getUser(); 
        if (!user) return;

        const isHead = user.RoleID === 1;

        // Config Theme
        const theme = isHead
            ? {
                hexColor: '#7c3aed',
                iconBg: '#7c3aed',
                title: 'HEAD NURSE',
                sub: 'ADMINISTRATION',
                homeLink: 'Headnurse_dashboard.html',
                notiLink: 'Admin_Approvals.html',
                userIcon: 'fa-user-md',
            }
            : {
                hexColor: '#4f46e5',
                iconBg: '#4f46e5',
                title: `สวัสดี ${user.FirstName}`, 
                sub: 'NURSE SYSTEM',
                homeLink: 'dashboard.html',
                notiLink: 'notifications.html', 
                userIcon: 'fa-user-nurse',
            };

        this.innerHTML = `
        <header class="bg-white sticky top-0 w-full shadow-sm" style="z-index: 2000 !important; border-top: 4px solid ${theme.hexColor};">
            <div class="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center relative">
                
                <a href="${theme.homeLink}" class="flex items-center gap-3 shrink-0">
                    <div class="w-10 h-10 rounded-xl flex items-center justify-center text-white shadow-md transition-transform hover:scale-105"
                         style="background-color: ${theme.iconBg};">
                        <i class="fas ${theme.userIcon} text-lg"></i> 
                    </div>
                    <div class="flex flex-col">
                        <h1 class="text-sm sm:text-lg font-bold text-slate-800 leading-none">${theme.title}</h1>
                        <p class="text-[9px] text-slate-400 font-medium tracking-wide mt-1 uppercase">${theme.sub}</p>
                    </div>
                </a>

                <div class="flex items-center gap-3 sm:gap-5 shrink-0">
                    
                    <div class="relative inline-block">
                        <button id="noti-trigger" class="relative p-2 rounded-full hover:bg-slate-50 transition-all group focus:outline-none">
                            <i class="fas fa-bell text-2xl text-slate-400 transition-colors group-hover:text-indigo-500"></i>
                            
                            <span id="unread-count" class="hidden absolute top-1 right-1 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white border-2 border-white shadow-sm ring-1 ring-red-200">
                                0
                            </span>
                        </button>

                        <div id="noti-dropdown" 
                             class="hidden absolute top-full left-1/2 -translate-x-1/2 mt-3 w-[92vw] sm:w-80 max-w-sm bg-white rounded-2xl shadow-2xl border border-slate-100 overflow-hidden origin-top transition-all duration-200" 
                             style="z-index: 2001;">
                            
                            <div class="px-4 py-3 border-b border-slate-50 bg-slate-50 flex justify-between items-center">
                                <h3 class="text-sm font-bold text-slate-700">การแจ้งเตือน</h3>
                                <span class="text-[10px] text-slate-400">ล่าสุด</span>
                            </div>
                            
                            <div id="noti-list" class="max-h-80 overflow-y-auto custom-scrollbar">
                                <div class="p-4 text-center text-xs text-gray-400">กำลังโหลด...</div>
                            </div>
                            
                            <a href="${theme.notiLink}" class="block bg-slate-50 py-3 text-center text-xs font-bold text-indigo-500 hover:text-indigo-600 hover:bg-slate-100 border-t border-slate-100 transition-colors">
                                ดูทั้งหมด
                            </a>
                        </div>
                    </div>

                    <div id="profile-menu-trigger" class="relative flex items-center gap-2 cursor-pointer bg-white hover:bg-slate-50 py-1 pl-1 pr-3 rounded-full border border-slate-200 shadow-sm transition-all min-w-fit">
                        <img id="header-avatar" 
                             class="w-8 h-8 rounded-full object-cover border border-slate-100 shadow-sm shrink-0" 
                             src="${getProfileImageUrl(user.ProfileImage)}" 
                             onerror="this.src='https://placehold.co/100?text=User'">
                        
                        <div class="flex flex-col items-start leading-tight">
                            <span class="text-[11px] font-medium text-slate-600 truncate max-w-[80px]">${user.FirstName}</span>
                            <span class="text-[7px] text-emerald-500 font-normal flex items-center gap-1 mt-0.5 tracking-tighter">
                                <span class="w-1 h-1 bg-emerald-400 rounded-full animate-pulse opacity-80"></span>
                                ONLINE
                            </span>
                        </div>
                        <i class="fas fa-chevron-down text-[7px] text-slate-400 ml-0.5 shrink-0"></i>
                    </div>

                </div>
            </div>
        </header>`;
        this.setupProfileLogic(user);
        this.setupNotiLogic(user);
        this.fetchBadgeCount(user);
    }

    setupNotiLogic(user) {
        const trigger = this.querySelector('#noti-trigger');
        const dropdown = this.querySelector('#noti-dropdown');
        const listContainer = this.querySelector('#noti-list');

        trigger.addEventListener('click', async (e) => {
            e.stopPropagation();
            const profileDropdown = document.getElementById('global-custom-dropdown');
            if(profileDropdown) profileDropdown.classList.add('hidden');

            dropdown.classList.toggle('hidden');

            if (!dropdown.classList.contains('hidden')) {
                await this.loadNotificationsInDropdown(user, listContainer);
            }
        });

        document.addEventListener('click', (e) => {
            if (!dropdown.contains(e.target) && !trigger.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });
    }

    async loadNotificationsInDropdown(user, container) {
        try {
            const token = localStorage.getItem('authToken');
            const res = await fetch(`${API_BASE}/api/notifications/all/${user.UserID}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (!res.ok) throw new Error("Load failed");
            const data = await res.json();

            container.innerHTML = ""; 

            if (!data.success || data.notifications.length === 0) {
                container.innerHTML = `<div class="p-10 text-center text-slate-400 text-xs">ไม่มีการแจ้งเตือนใหม่</div>`;
                return;
            }

            data.notifications.slice(0, 5).forEach(noti => {
                const timeAgo = new Date(noti.created_at).toLocaleString('th-TH', { 
                    timeZone: 'Asia/Bangkok', day: 'numeric', month: 'short', hour: '2-digit', minute:'2-digit'
                });
                
                const isSystem = noti.type === 'system';
                const iconBg = isSystem ? 'bg-blue-50 text-blue-500' : 'bg-orange-50 text-orange-500';

                container.innerHTML += `
                <div class="px-4 py-3 border-b border-slate-50 hover:bg-slate-50 cursor-pointer transition-colors" onclick="window.location.href='notifications.html'">
                    <div class="flex gap-3 items-start">
                        <div class="w-8 h-8 rounded-full ${iconBg} flex items-center justify-center shrink-0 text-[10px]">
                            <i class="fas ${isSystem ? 'fa-check' : 'fa-exchange-alt'}"></i>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex justify-between items-center gap-2">
                                <h4 class="text-xs font-bold text-slate-800 truncate">${isSystem ? noti.LastName : noti.FirstName}</h4>
                                <span class="text-[9px] text-slate-400 whitespace-nowrap">${timeAgo}</span>
                            </div>
                            <p class="text-[10px] text-slate-500 truncate mt-0.5 font-light">${noti.info}</p>
                        </div>
                    </div>
                </div>`;
            });
        } catch (err) { container.innerHTML = '<div class="p-4 text-center text-xs text-red-400">เกิดข้อผิดพลาด</div>'; }
    }

    async fetchBadgeCount(user) {
        try {
            const token = localStorage.getItem('authToken');
            const isHead = user.RoleID === 1;
            const endpoint = isHead ? '/api/admin/pending-counts' : `/api/notifications/unread-count/${user.UserID}`;
            
            const res = await fetch(`${API_BASE}${endpoint}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (!res.ok) return;

            const data = await res.json();
            if (data.success) {
                const badge = this.querySelector('#unread-count');
                const count = isHead ? (data.total || 0) : (data.count || 0);
                if (count > 0) {
                    badge.innerText = count > 99 ? '99+' : count;
                    badge.classList.remove('hidden');
                } else {
                    badge.classList.add('hidden');
                }
            }
        } catch (err) { console.error("Badge Error:", err); }
    }

    setupProfileLogic(user) {
        const trigger = this.querySelector('#profile-menu-trigger');
        let dropdown = document.getElementById('global-custom-dropdown');

        if (!dropdown) {
            const dropdownHtml = `
            <div id="global-custom-dropdown" 
                class="hidden fixed w-44 bg-white rounded-2xl shadow-xl border border-slate-100 py-2 origin-top-right transition-all duration-200"
                style="z-index: 9999 !important;"> 
                <a href="profile-edit.html" class="flex items-center px-4 py-2 text-[12px] text-slate-600 hover:bg-slate-50">
                    <i class="fas fa-user-edit w-5 mr-2 text-indigo-500"></i> แก้ไขโปรไฟล์
                </a>
                <div class="border-t border-slate-100 my-1"></div>
                <button id="header-logout-btn" class="w-full text-left flex items-center px-4 py-2 text-[12px] text-red-500 hover:bg-red-50">
                    <i class="fas fa-sign-out-alt w-5 mr-2"></i> ออกจากระบบ
                </button>
            </div>`;
            document.body.insertAdjacentHTML('afterbegin', dropdownHtml);
            dropdown = document.getElementById('global-custom-dropdown');
        }

        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const notiDropdown = this.querySelector('#noti-dropdown');
            if(notiDropdown) notiDropdown.classList.add('hidden');

            const triggerRect = trigger.getBoundingClientRect();
            dropdown.style.top = `${triggerRect.bottom + 10}px`; 
            dropdown.style.right = `${window.innerWidth - triggerRect.right}px`;
            dropdown.classList.toggle('hidden');
        });

        document.addEventListener('click', () => dropdown.classList.add('hidden'));

        const logoutBtn = dropdown.querySelector('#header-logout-btn');
        logoutBtn.onclick = () => logout();
    }
}

if (!customElements.get('app-header')) {
    customElements.define('app-header', AppHeader);
}
// =========================================================

// --- App Navbar (เมนูล่าง - เปลี่ยนรายการเมนูตาม Role) ---
class AppNavbar extends HTMLElement {
    connectedCallback() {
        const user = getUser();
        if (!user) return;

        const isHead = user.RoleID === 1;
        
        // **Menu Config:** กำหนดรายการเมนูแยกตาม Role
        const headMenus = [
            { href: 'Headnurse_dashboard.html', icon: 'fa-chart-line', label: 'ภาพรวม' },
            { href: 'swap_request.html', icon: 'fa-exchange-alt', label: 'แลกเวร' },
            { href: 'trade_market.html', icon: 'fa-shopping-cart', label: 'ซื้อขาย' },
            { href: 'schedule.html', icon: 'fa-calendar-alt', label: 'ตารางเวร' },
            { href: 'nurse_list.html', icon: 'fa-user-nurse', label: 'บุคลากร' },
            { href: 'approve_swap.html', icon: 'fa-clipboard-check', label: 'อนุมัติ' },
        ];

        const nurseMenus = [
            { href: 'dashboard.html', icon: 'fa-home', label: 'หน้าหลัก' },
            { href: 'swap_request.html', icon: 'fa-exchange-alt', label: 'แลกเวร' },
            { href: 'trade_market.html', icon: 'fa-shopping-cart', label: 'ซื้อขาย' },
            { href: 'schedule.html', icon: 'fa-calendar-alt', label: 'ตารางเวร' },
            { href: 'statistics.html', icon: 'fa-chart-bar', label: 'สถิติ' },
        ];

        const menus = isHead ? headMenus : nurseMenus;
        
        // สี Active ของเมนู
        const activeColor = isHead ? 'text-violet-600' : 'text-indigo-600';
        const barColor = isHead ? 'bg-violet-600' : 'bg-indigo-600';

        // Generate Menu Items HTML
        const menuHtml = menus.map(m => {
            // เช็คว่า URL ปัจจุบันตรงกับเมนูไหน (Active State)
            const isActive = window.location.href.includes(m.href);
            
            return `
            <a href="${m.href}" class="flex flex-col items-center justify-center relative w-full h-full group transition-all duration-200 ${isActive ? activeColor : 'text-gray-400 hover:text-gray-600'}">
                ${isActive ? `<div class="absolute top-0 w-8 h-1 ${barColor} rounded-b-lg shadow-sm"></div>` : ''}
                <i class="fas ${m.icon} text-xl mb-1 transition-transform group-hover:-translate-y-1"></i>
                <span class="text-[10px] font-medium">${m.label}</span>
            </a>
            `;
        }).join('');

        this.innerHTML = `
        <nav class="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-100 pb-safe z-50 shadow-[0_-4px_20px_rgba(0,0,0,0.03)]">
            <div class="max-w-screen-md mx-auto flex justify-between items-center h-16 px-1">
                ${menuHtml}
            </div>
        </nav>`;
    }
}
customElements.define('app-navbar', AppNavbar);


// --- Date Picker Component (Reusable) ---
class AppDatePicker extends HTMLElement {
    connectedCallback() {
        const placeholder = this.getAttribute('placeholder') || 'เลือกวันที่...';
        const id = this.getAttribute('input-id') || 'datepicker-' + Math.random().toString(36).substr(2, 9);
        
        this.innerHTML = `
            <div class="relative group">
                <input type="text" id="${id}" class="w-full bg-white border-2 border-gray-100 rounded-xl px-4 py-3 pl-11 text-sm font-medium text-gray-700 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition outline-none cursor-pointer" placeholder="${placeholder}">
                <i class="fas fa-calendar-alt absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 group-hover:text-indigo-500 transition-colors pointer-events-none"></i>
            </div>`;
        
        // Init Flatpickr (รอให้ DOM โหลดเสร็จนิดนึง)
        setTimeout(() => {
            if (typeof flatpickr !== 'undefined') {
                flatpickr(`#${id}`, {
                    locale: "th", dateFormat: "Y-m-d", altInput: true, altFormat: "j F Y", disableMobile: true,
                    onChange: (selectedDates, dateStr) => {
                        // Dispatch Custom Event เพื่อให้หน้าหลักรู้ว่าค่าเปลี่ยน
                        this.dispatchEvent(new CustomEvent('date-change', { detail: { date: dateStr } }));
                    }
                });
            }
        }, 0);
    }
}
customElements.define('app-date-picker', AppDatePicker);


// =========================================================
// 3. AUTO LOGOUT SYSTEM (Global Idle Timeout - 15 Minutes)
// =========================================================
(function() {
    const IDLE_TIMEOUT = 15 * 60 * 1000; // 15 นาที
    let idleTimer;

    const performLogout = () => {
        const user = getUser();
        if (!user) return;

        // ล้างข้อมูลในเครื่องทันทีเพื่อความปลอดภัย
        localStorage.removeItem('token');
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');

        if (typeof Swal !== 'undefined') {
            Swal.fire({
                icon: 'warning',
                title: 'หมดเวลาการใช้งาน',
                text: 'คุณไม่ได้ทำรายการเกิน 15 นาที ระบบจะนำคุณกลับไปหน้า Login',
                timer: 4000,
                timerProgressBar: true,
                showConfirmButton: false,
                allowOutsideClick: false, // บังคับให้ดูแจ้งเตือนจนกว่าจะ Redirect
                allowEscapeKey: false
            }).then(() => {
                window.location.href = 'login.html';
            });
        } else {
            alert('หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
            window.location.href = 'login.html';
        }
    };

    const resetTimer = () => {
        // ถ้าไม่ได้ Login อยู่แล้ว ไม่ต้องรัน Timer
        if (!localStorage.getItem('user')) return;
        
        clearTimeout(idleTimer);
        idleTimer = setTimeout(performLogout, IDLE_TIMEOUT);
    };

    // ตรวจสอบเหตุการณ์ที่แสดงว่าผู้ใช้ยังใช้งานอยู่ (Activity Events)
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    events.forEach(evt => {
        document.addEventListener(evt, resetTimer, { passive: true });
    });
    
    // เริ่มต้นทำงานครั้งแรก
    resetTimer();
})();
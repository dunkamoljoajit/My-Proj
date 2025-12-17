// =========================================================
// 1. CONFIG & UTILITIES
// =========================================================
const API_BASE = 'http://localhost:3000'; 

// ฟังก์ชันช่วยดึงข้อมูลผู้ใช้และ Token
const getUser = () => {
    try {
        const userStr = localStorage.getItem('user');
        return userStr ? JSON.parse(userStr) : null;
    } catch (e) {
        console.error("Error parsing user data:", e);
        return null;
    }
};

const getToken = () => localStorage.getItem('authToken');

// ฟังก์ชันจัดการ URL รูปภาพ (รองรับทั้ง Local และ Cloudinary)
const getProfileImageUrl = (imagePath) => {
    if (!imagePath) return 'https://placehold.co/100?text=User';
    // ถ้าเป็น Link เต็มๆ (http...) ให้ใช้เลย, ถ้าไม่ ให้ต่อ Path ของ Local
    return imagePath.startsWith('http') ? imagePath : `${API_BASE}/uploads/${imagePath}`;
};

// ฟังก์ชัน Logout กลาง (ใช้ร่วมกันทุกหน้า)
const logout = () => {
    const confirmLogout = async () => {
        const user = getUser();
        const token = getToken();

        if (user && user.UserID) {
            try {
                await fetch(`${API_BASE}/api/logout`, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}` 
                    },
                    body: JSON.stringify({ userId: user.UserID })
                });
            } catch (err) {
                console.error("Logout API Error:", err);
            }
        }
        localStorage.clear();
        window.location.href = 'login.html';
    };

    if (typeof Swal !== 'undefined') {
        Swal.fire({
            title: 'ออกจากระบบ?',
            text: 'คุณต้องการออกจากระบบใช่หรือไม่',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#94a3b8',
            confirmButtonText: 'ใช่, ออก',
            cancelButtonText: 'ยกเลิก',
            customClass: { popup: 'rounded-2xl', confirmButton: 'rounded-xl', cancelButton: 'rounded-xl' }
        }).then((result) => { if (result.isConfirmed) confirmLogout(); });
    } else {
        if (confirm("คุณต้องการออกจากระบบใช่หรือไม่?")) confirmLogout();
    }
};


// =========================================================
// 2. WEB COMPONENTS (Smart Components)
// =========================================================

// --- App Layout (โครงสร้างหลัก) ---
class AppLayout extends HTMLElement {
    connectedCallback() {
        // เพิ่ม Font อัตโนมัติถ้ายังไม่มี
        if (!document.getElementById('app-fonts')) {
            const fontLink = document.createElement('link');
            fontLink.id = 'app-fonts';
            fontLink.rel = 'stylesheet';
            fontLink.href = 'https://fonts.googleapis.com/css2?family=Kanit:wght@200;300;400;500;600;700&display=swap';
            document.head.appendChild(fontLink);
        }

        const content = this.innerHTML;
        this.className = "flex flex-col min-h-screen text-slate-800 antialiased font-sans bg-[#f0fdfa]"; // สีพื้นหลังเริ่มต้น
        
        // Render โครงสร้าง: Header -> Main Content -> Navbar
        this.innerHTML = `
            <app-header></app-header>
            <main class="flex-1 w-full max-w-7xl mx-auto p-4 md:p-6 lg:p-8 pb-32 overflow-y-auto scroll-smooth">
                ${content}
            </main>
            <app-navbar></app-navbar>
        `;
    }
}
customElements.define('app-layout', AppLayout);


// --- App Header (หัวเว็บ - เปลี่ยนสี/ข้อความตาม Role) ---
// =========================================================
// 2. WEB COMPONENTS (Smart Components)
// =========================================================

// --- App Header (หัวเว็บ - เปลี่ยนสี/ข้อความตาม Role) ---
class AppHeader extends HTMLElement {

    connectedCallback() {
        // ต้องตรวจสอบให้แน่ใจว่าฟังก์ชัน getUser() มีอยู่
        const user = getUser(); 
        if (!user) return;

        const isHead = user.RoleID === 1;

        // 1. Theme Config
        const theme = isHead
            ? {
                // Config สำหรับ Head Nurse (Role 1)
                bgIcon: 'bg-violet-600',
                shadow: 'shadow-violet-200',
                title: 'HEAD NURSE',
                sub: 'ADMINISTRATION',
                homeLink: 'Headnurse_dashboard.html',
                statusColor: 'text-emerald-500',
                headerBorder: 'border-t-4 border-violet-600',
                userIcon: 'fa-user-md',
            }
            : {
                // Config สำหรับ Nurse (Role 2)
                bgIcon: 'bg-indigo-600',
                shadow: 'shadow-indigo-200',
                title: `สวัสดี ${user.FirstName}`, 
                sub: typeof moment !== 'undefined' ? moment().locale('th').format('D MMMM YYYY') : 'วันที่ปัจจุบัน',
                homeLink: 'dashboard.html',
                statusColor: 'text-emerald-500',
                headerBorder: 'border-t-4 border-indigo-600',
                userIcon: 'fa-user-nurse',
            };

        // 2. วันที่สำหรับ Head Nurse
        const dateDisplayHtml = isHead 
            ? `<div class="hidden sm:block text-right">
                <p class="text-xs text-slate-400 mt-1" id="header-date">...</p>
               </div>` 
            : '';

        // 3. Render HTML
        this.innerHTML = `
        <header class="bg-white sticky top-0 z-50 shadow-sm ${theme.headerBorder} transition-all duration-300">
            <div class="max-w-screen-md mx-auto px-4 py-3 flex justify-between items-center">
                
                <a href="${theme.homeLink}" class="flex items-center gap-3 group">
                    <div class="w-10 h-10 ${theme.bgIcon} rounded-xl flex items-center justify-center text-white shadow-md ${theme.shadow} transition-transform group-hover:scale-105">
                        <i class="fas ${theme.userIcon} text-lg"></i> </div>
                    <div>
                        <h1 class="text-lg font-bold text-slate-800 leading-none">${theme.title}</h1>
                        <p class="text-[10px] text-slate-400 font-medium tracking-wide mt-0.5 uppercase">${theme.sub}</p>
                    </div>
                </a>

                <div class="flex items-center gap-4">
                    
                    <div id="right-elements-wrapper" class="flex items-center gap-4">
                        
                        ${dateDisplayHtml}

                        <div id="profile-menu-trigger" class="relative z-10 flex items-center gap-3 cursor-pointer bg-white hover:bg-slate-50 px-1 py-1 rounded-full border border-slate-100 shadow-sm transition-all select-none pr-4">
                            <img id="header-avatar" class="w-9 h-9 rounded-full object-cover border-2 border-white shadow-sm" src="${getProfileImageUrl(user.ProfileImage)}" onerror="this.src='https://placehold.co/100?text=User'">
                            
                            <div class="text-right hidden sm:block">
                                <p class="text-xs font-bold text-slate-700 leading-none">${user.FirstName} ${user.LastName}</p>
                                <p class="text-[9px] ${theme.statusColor} font-bold mt-0.5">● Online</p>
                            </div>
                        </div>

                    </div>
                </div>
            </div>
        </header>`;

        this.setupLogic(user, isHead);
    }

    setupLogic(user, isHead) {
        // 1. ตั้งค่าวันที่ (ยังคงเดิม)
        if(isHead) {
            const dateEl = this.querySelector('#header-date');
            if(dateEl) {
                if(typeof moment !== 'undefined') {
                    dateEl.innerText = moment().locale('th').format('วันddddที่ D MMMM YYYY');
                } else {
                    dateEl.innerText = new Date().toLocaleDateString('th-TH', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
                }
            }
        }

        // 2. สร้าง Dropdown Menu แบบ Dynamic (ใช้ FIXED POSITION)
        const trigger = this.querySelector('#profile-menu-trigger');
        if(trigger) {
            let dropdown = document.getElementById('global-custom-dropdown');

            // แก้ไขส่วนสร้าง Dropdown
            if (!dropdown) {
                const dropdownHtml = `
                <div id="global-custom-dropdown" 
                    class="hidden fixed w-56 bg-white rounded-2xl shadow-xl border border-slate-100 py-2 origin-top-right transition-all duration-200"
                    style="z-index: 999999 !important;"> 
                    
                    <a href="profile-edit.html" class="flex items-center px-4 py-2.5 text-sm text-slate-600 hover:bg-slate-50 hover:text-indigo-600 transition-colors">
                        <i class="fas fa-user-edit w-5 mr-2 text-indigo-500 opacity-80"></i> แก้ไขโปรไฟล์
                    </a>
                    <div class="border-t border-slate-100 my-1"></div>
                    <button id="header-logout-btn" class="w-full text-left flex items-center px-4 py-2.5 text-sm text-red-500 hover:bg-red-50 transition-colors">
                        <i class="fas fa-sign-out-alt w-5 mr-2 opacity-80"></i> ออกจากระบบ
                    </button>
                </div>`;
                
                // เปลี่ยนมาวางไว้หน้าสุดของ body เพื่อเลี่ยงการโดน element อื่นในลำดับท้ายๆ ทับ
                document.body.insertAdjacentHTML('afterbegin', dropdownHtml);
                dropdown = document.getElementById('global-custom-dropdown');
            }

            
            // 2.2 Event Listener: คำนวณตำแหน่งด้วย JS ทุกครั้งที่คลิก (ใช้ Fixed)
           trigger.addEventListener('click', (e) => {
                e.stopPropagation();
                const triggerRect = trigger.getBoundingClientRect();
                
                dropdown.style.top = `${triggerRect.bottom + 10}px`; 
                dropdown.style.right = `${window.innerWidth - triggerRect.right}px`;
                
                // บังคับผ่าน JS เมื่อกดเปิด
                dropdown.style.zIndex = "999999";
                dropdown.style.display = dropdown.classList.contains('hidden') ? 'block' : 'none';
                
                dropdown.classList.toggle('hidden');
            });

            // 2.3 Event Listener สำหรับการคลิกนอก Dropdown (เพื่อปิด)
            document.addEventListener('click', (e) => {
                // ตรวจสอบทั้ง Trigger และ Dropdown
                if (dropdown && !trigger.contains(e.target) && !dropdown.contains(e.target)) {
                    dropdown.classList.add('hidden');
                }
            });

            // 2.4 Event Listener สำหรับปุ่ม Logout
            const logoutBtn = dropdown.querySelector('#header-logout-btn');
            if(logoutBtn) {
                logoutBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    if (typeof logout === 'function') {
                        logout();
                    } else {
                        console.error('Logout function is not defined.');
                    }
                });
            }
        }
    }
}

// *** การลงทะเบียน Custom Element (ต้องอยู่ท้ายสุดของโค้ดคลาส) ***
if (!customElements.get('app-header')) {
    customElements.define('app-header', AppHeader);
}

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
// 3. AUTO LOGOUT SYSTEM (Global Idle Timeout)
// =========================================================
(function() {
    const IDLE_TIMEOUT = 15 * 60 * 1000; // 15 นาที
    let idleTimer;

    const resetTimer = () => {
        if (!localStorage.getItem('user')) return;
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            // Logic Auto Logout
            const user = getUser();
            if (user) {
                // แจ้งเตือนหรือบังคับออกเลยก็ได้
                if (typeof Swal !== 'undefined') {
                    Swal.fire({
                        icon: 'warning', title: 'หมดเวลาการใช้งาน', text: 'กรุณาเข้าสู่ระบบใหม่',
                        timer: 3000, showConfirmButton: false
                    }).then(() => { localStorage.clear(); window.location.href = 'login.html'; });
                } else {
                    alert('หมดเวลาการใช้งาน'); localStorage.clear(); window.location.href = 'login.html';
                }
            }
        }, IDLE_TIMEOUT);
    };

    // Events ที่จะ Reset Timer
    ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(evt => {
        document.addEventListener(evt, resetTimer, true);
    });
    
    resetTimer(); // Start Timer
})();
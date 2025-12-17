const express = require('express');
const app = express();
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken'); 
const xlsx = require('xlsx');
const port = 3000; 
// Library สำหรับ Vercel/Cloudinary ---
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;

// --- Middleware ---
app.use(cors());
app.use(express.json()); 

// ==========================================
// 1. CONFIGURATION: Cloudinary (เก็บรูปภาพ)
// ==========================================
// ต้องไปตั้งค่า CLOUDINARY_ ใน .env หรือ Vercel Environment Variables
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'autonurseshift-profiles', // ชื่อโฟลเดอร์บน Cloudinary
        allowed_formats: ['jpg', 'png', 'jpeg'],
    },
});
const upload = multer({ storage: storage });

// ==========================================
// 2. CONFIGURATION: Excel Upload (เก็บใน RAM)
// ==========================================
const excelStorage = multer.memoryStorage();
const excelFilter = (req, file, cb) => {
    if (file.mimetype.includes('excel') || file.mimetype.includes('spreadsheetml')) {
        cb(null, true);
    } else {
        cb(new Error('กรุณาอัปโหลดเฉพาะไฟล์ Excel (.xlsx)'), false);
    }
};
const uploadExcel = multer({ storage: excelStorage, fileFilter: excelFilter });

// ==========================================
// 3. DATABASE CONNECTION (TiDB Cloud SSL)
// ==========================================
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || 4000, 
    waitForConnections: true,
    connectionLimit: 10,        
    queueLimit: 0,
    enableKeepAlive: true,
    // [สำคัญ] TiDB บังคับเปิด SSL
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    }
};

const dbPool = mysql.createPool(dbConfig).promise();

// --- Email Config ---
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: true,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// ==========================================
// 4. HELPER FUNCTIONS
// ==========================================

async function logLoginAttempt(dbPool, data) {
    try {
        const { UserID, Email, IP, Status, FailureReason } = data;
        const sql = `INSERT INTO LoginLog (UserID, AttemptedEmail, Status, IP_Address, FailureReason, CreatedAt) VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        await dbPool.query(sql, [UserID || null, Email, Status, IP, FailureReason || null]);
    } catch (err) { console.error("Log Error:", err.message); }
}

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateRandomPassword(length = 8) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let retVal = "";
    for (let i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    return retVal;
}

function getThaiTimeInMySQLFormat(addMinutes = 0) {
    const now = new Date();
    if (addMinutes > 0) now.setMinutes(now.getMinutes() + addMinutes);
    return now.toLocaleString('sv-SE', { timeZone: 'Asia/Bangkok' }).replace('T', ' ');
}

// --- Security Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (!token) return res.status(401).json({ success: false, message: 'Access Denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid Token' });
        req.user = user; 
        next();
    });
};

// ==========================================
// 5. API ROUTES
// ==========================================

// Get Roles
app.get('/api/roles', async (req, res) => {
    try {
        const [roles] = await dbPool.query("SELECT RoleID, Role FROM Role WHERE RoleID IN (1, 2)");
        res.json(roles);
    } catch (err) {
        console.error(err); res.status(500).send({ message: 'Error fetching roles' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
    const { Email, Password } = req.body;
    if (!Email || !Password) return res.status(400).send({ message: 'กรุณากรอกข้อมูล' });

    try {
        const [users] = await dbPool.query("SELECT UserID, FirstName, LastName, PasswordHash, RoleID, ProfileImage FROM User WHERE Email = ?", [Email]);

        if (users.length === 0) {
            await logLoginAttempt(dbPool, { Email, IP: ipAddress, Status: 'Failed', FailureReason: 'User not found' });
            return res.status(401).send({ message: 'ไม่พบผู้ใช้' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(Password, user.PasswordHash);

        if (!isMatch) {
            await logLoginAttempt(dbPool, { UserID: user.UserID, Email, IP: ipAddress, Status: 'Failed', FailureReason: 'Invalid password' });
            return res.status(401).send({ message: 'รหัสผ่านไม่ถูกต้อง' });
        }

        await dbPool.query("UPDATE User SET Status = 'active' WHERE UserID = ?", [user.UserID]);
        await logLoginAttempt(dbPool, { UserID: user.UserID, Email, IP: ipAddress, Status: 'Success' });
        
        const token = jwt.sign(
            { userId: user.UserID, roleId: user.RoleID, email: Email }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        const { PasswordHash, ...userData } = user;
        userData.Status = 'active';
        res.status(200).json({ message: 'ล็อกอินสำเร็จ', status: 'success', token: token, user: userData });

    } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Server Error' });
    }
});

// Logout
app.post('/logout', async (req, res) => {
    const userId = req.body.userId;
    console.log("--> Logout Request Received:", userId);

    try {
        const [result] = await dbPool.query(
            "UPDATE User SET Status = 'inactive' WHERE UserID = ?", 
            [userId]
        );
        res.clearCookie('token');
        res.json({ message: "Logged out successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

//  API Update Profile Image (ใช้ Cloudinary URL)
app.post('/api/update-profile-image', authenticateToken, upload.single('profileImage'), async (req, res) => {
    const userId = req.body.userId;
    // Cloudinary จะเก็บ URL ไว้ใน req.file.path
    if (!userId || !req.file) return res.status(400).json({ success: false, message: "Missing data" });

    try {
        // ใช้ path เต็ม (URL จาก Cloudinary)
        const imagePath = req.file.path; 
        await dbPool.query("UPDATE User SET ProfileImage = ? WHERE UserID = ?", [imagePath, userId]);
        res.json({ success: true, message: "อัปโหลดสำเร็จ", imagePath: imagePath });
    } catch (err) {
        console.error(err); res.status(500).json({ success: false, message: err.message });
    }
});

// Forgot Password
app.post('/api/forgot-password', async (req, res) => {
    const { Email } = req.body;
    if (!Email) return res.status(400).send({ message: 'กรุณากรอกอีเมล' });

    try {
        const [users] = await dbPool.query('SELECT UserID FROM User WHERE Email = ?', [Email]);
        if (users.length === 0) return res.status(404).send({ message: 'ไม่พบผู้ใช้' });

        const user = users[0];
        const otp = generateOTP();
        const createdAt = getThaiTimeInMySQLFormat(0);
        const expiresAt = getThaiTimeInMySQLFormat(10);

        await dbPool.query('INSERT INTO Password_reset_otp (UserID, otp_code, created_at, expires_at, is_used) VALUES (?, ?, ?, ?, ?)', 
            [user.UserID, otp, createdAt, expiresAt, false]);

        const mailOptions = {
            from: `"AUTONURSESHIFT" <${process.env.EMAIL_USER}>`,
            to: Email,
            subject: 'รหัส OTP สำหรับรีเซ็ตรหัสผ่าน',
            html: `<p>รหัส OTP ของคุณคือ: <b>${otp}</b></p>`
        };
        await transporter.sendMail(mailOptions);
        res.status(200).send({ message: 'ส่ง OTP แล้ว' });

    } catch (err) { console.error(err); res.status(500).send({ message: err.message }); }
});

// Verify OTP
app.post("/verify-otp", async (req, res) => {
    const { email, otp } = req.body;
    try {
        const [users] = await dbPool.query("SELECT UserID FROM User WHERE Email = ?", [email]);
        if (users.length === 0) return res.status(404).json({ success: false, message: "ไม่พบผู้ใช้" });

        const [otps] = await dbPool.query("SELECT * FROM Password_reset_otp WHERE UserID = ? ORDER BY otp_id DESC LIMIT 1", [users[0].UserID]);
        if (otps.length === 0) return res.status(400).json({ success: false, message: "ขอ OTP ใหม่" });

        const otpData = otps[0];
        if (otpData.otp_code !== otp || otpData.is_used === 1) return res.status(400).json({ success: false, message: "OTP ไม่ถูกต้อง" });
        
        if (getThaiTimeInMySQLFormat(0) > new Date(otpData.expires_at).toLocaleString('sv-SE')) {
            return res.status(400).json({ success: false, message: "OTP หมดอายุ" });
        }

        res.json({ success: true, message: "OTP ถูกต้อง" });
    } catch (err) { res.status(500).json({ success: false, message: "Server Error" }); }
});

// Reset Password
app.post("/api/reset-password", async (req, res) => {
    const { email, newPassword, otp } = req.body;
    try {
        const [users] = await dbPool.query("SELECT UserID FROM User WHERE Email = ?", [email]);
        if (users.length === 0) return res.status(404).json({ success: false });

        const userId = users[0].UserID;
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await dbPool.query("UPDATE User SET PasswordHash = ? WHERE UserID = ?", [hashedPassword, userId]);
        await dbPool.query("UPDATE Password_reset_otp SET is_used = 1 WHERE UserID = ? AND otp_code = ?", [userId, otp]);

        res.json({ success: true, message: "เปลี่ยนรหัสผ่านสำเร็จ" });
    } catch (err) { res.status(500).json({ success: false, message: "Server Error" }); }
});

// [แก้จุดที่ 2] API Import Users (อ่านจาก Buffer แทนไฟล์)
app.post('/api/admin/import-users', authenticateToken, uploadExcel.single('file'), async (req, res) => {
    try {
        if (req.user.roleId !== 1) { 
            return res.status(403).json({ success: false, message: 'Access Denied: Admins only' });
        }

        if (!req.file) {
            return res.status(400).json({ success: false, message: 'กรุณาเลือกไฟล์ Excel (.xlsx)' });
        }

        // อ่านจาก RAM (Buffer) เพราะ Vercel ห้ามเขียนไฟล์
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const sheet = workbook.Sheets[workbook.SheetNames[0]];
        const data = xlsx.utils.sheet_to_json(sheet);

        if (data.length === 0) {
            return res.status(400).json({ success: false, message: 'ไฟล์ไม่มีข้อมูล' });
        }

        let successCount = 0;
        let failCount = 0;
        let importedList = [];
        let errorDetails = [];

        for (const [index, row] of data.entries()) {
            const email = row['Email'] ? String(row['Email']).trim() : null;
            const firstName = row['FirstName'] ? String(row['FirstName']).trim() : null;
            const lastName = row['LastName'] ? String(row['LastName']).trim() : '';
            const roleId = row['RoleID'] || 2; 

            if (!email || !firstName) {
                failCount++;
                errorDetails.push(`Row ${index + 2}: ข้อมูลไม่ครบ`);
                continue;
            }

            try {
                const rawPassword = generateRandomPassword(8);
                const hashedPassword = await bcrypt.hash(rawPassword, 10);
                const sql = `INSERT INTO User (Email, PasswordHash, FirstName, LastName, RoleID, Status, CreatedAt) VALUES (?, ?, ?, ?, ?, 'active', DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
                
                await dbPool.query(sql, [email, hashedPassword, firstName, lastName, roleId, deptId]);

                const mailOptions = {
                    from: `"AUTONURSESHIFT" <${process.env.EMAIL_USER}>`,
                    to: email,
                    subject: 'ข้อมูลเข้าสู่ระบบใหม่ - AUTONURSESHIFT',
                    html: `<div style="padding: 20px; border: 1px solid #ddd; border-radius: 10px;"><h2>ยินดีต้อนรับ ${firstName}</h2><p>Email: ${email}</p><p>Password: ${rawPassword}</p></div>`
                };

                try {
                    await transporter.sendMail(mailOptions);
                } catch (mailErr) {
                    errorDetails.push(`${email}: สร้าง User สำเร็จ แต่ส่งเมลไม่ผ่าน`);
                }

                successCount++;
                importedList.push({ email: email, name: `${firstName} ${lastName}` });

            } catch (err) {
                failCount++;
                if (err.code === 'ER_DUP_ENTRY') {
                    errorDetails.push(`${email}: มีในระบบแล้ว`);
                } else {
                    errorDetails.push(`${email}: Database Error`);
                }
            }
        }

        res.json({
            success: true,
            message: `ประมวลผลเสร็จสิ้น`,
            summary: { total: data.length, success: successCount, failed: failCount },
            newUsers: importedList, 
            errors: errorDetails
        });

    } catch (err) {
        console.error("Import Error:", err);
        res.status(500).json({ success: false, message: 'Server Error: ' + err.message });
    }
});

// ==========================================
// 6. DASHBOARD & ADMIN APIs (Logic เดิมใช้ได้)
// ==========================================
app.post('/api/dashboard-summary', authenticateToken, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: "UserID required" });

    try {
        const [[user]] = await dbPool.query("SELECT FirstName, LastName, ProfileImage FROM User WHERE UserID = ?", [userId]);
        if (!user) return res.status(404).json({ message: "User not found" });

        const [monthRes, weekRes, exchangeRes, tradeRes, upcomingRes] = await Promise.all([
            dbPool.query(`SELECT COUNT(*) as count FROM NurseSchedule WHERE UserID = ? AND MONTH(Nurse_Date) = MONTH(CURRENT_DATE())`, [userId]),
            dbPool.query(`SELECT COUNT(*) as count FROM NurseSchedule WHERE UserID = ? AND YEARWEEK(Nurse_Date, 1) = YEARWEEK(CURRENT_DATE(), 1)`, [userId]),
            dbPool.query(`SELECT COUNT(*) as count FROM Shift_Exchange WHERE requester_id = ? AND status = 'pending'`, [userId]),
            dbPool.query(`SELECT COUNT(*) as count FROM ShiftTransaction WHERE SellerID = ? AND Status = 'Pending'`, [userId]),
            dbPool.query(`SELECT NS.Nurse_Date, S.ShiftName, S.StartTime, S.EndTime FROM NurseSchedule NS JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE NS.UserID = ? AND NS.Nurse_Date >= CURRENT_DATE() ORDER BY NS.Nurse_Date ASC LIMIT 2`, [userId])
        ]);

        res.json({
            success: true,
            userData: { fullName: `${user.FirstName} ${user.LastName}`, profileImage: user.ProfileImage },
            stats: { 
                totalMonth: monthRes[0][0].count, 
                totalWeek: weekRes[0][0].count, 
                pendingExchange: exchangeRes[0][0].count, 
                pendingTrade: tradeRes[0][0].count 
            },
            upcomingShifts: upcomingRes[0] 
        });
    } catch (err) { console.error(err); res.status(500).json({ message: "Server Error" }); }
});

app.get('/api/check-constraint-window', authenticateToken, async (req, res) => { try { const [resDb] = await dbPool.query("SELECT SettingValue FROM SystemSettings WHERE SettingKey = 'WindowStatus'"); res.json({ isOpen: resDb.length > 0 && resDb[0].SettingValue === 'Open' }); } catch (err) { res.json({ isOpen: false }); } });
app.post('/api/admin/toggle-window', authenticateToken, async (req, res) => { 
    try { 
        // ใช้ INSERT ... ON DUPLICATE KEY UPDATE 
        // (แปลว่า: ให้สร้างข้อมูลใหม่ ถ้ามีอยู่แล้วให้อัปเดตค่า)
        await dbPool.query(`
            INSERT INTO SystemSettings (SettingKey, SettingValue) 
            VALUES ('WindowStatus', ?) 
            ON DUPLICATE KEY UPDATE SettingValue = VALUES(SettingValue)
        `, [req.body.status]); 
        
        res.json({ success: true }); 
    } catch (err) { 
        console.error("Toggle Window Error:", err);
        res.status(500).json({ success: false }); 
    } 
});
app.post('/api/notifications/mark-all-read', authenticateToken, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: "Missing UserID" });

    try {
        // อัปเดตทุกรายการแจ้งเตือนของ User นั้นๆ ที่ยังไม่อ่าน (IsRead = 0) ให้เป็นอ่านแล้ว (IsRead = 1)
        await dbPool.query(
            "UPDATE Notifications SET IsRead = 1 WHERE UserID = ? AND IsRead = 0",
            [userId]
        );
        res.json({ success: true, message: "ทำเครื่องหมายว่าอ่านแล้วทั้งหมดเรียบร้อย" });
    } catch (err) {
        console.error("Mark Read Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
// ✅ เพิ่ม API นี้เข้าไปใน index.js เพื่อแก้ Error 404
app.get('/api/notifications/unread-count/:userId', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        // นับเฉพาะรายการแจ้งเตือนที่ UserID ตรงกัน และ IsRead ยังเป็น 0 (ยังไม่อ่าน)
        const [rows] = await dbPool.query(
            "SELECT COUNT(*) as count FROM Notifications WHERE UserID = ? AND IsRead = 0",
            [userId]
        );
        
        res.json({ 
            success: true, 
            count: rows[0].count 
        });
    } catch (err) { 
        console.error("Unread Count API Error:", err);
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});
// ✅ แก้ไข API นับจำนวน Badge หัวหน้า
app.get('/api/admin/pending-counts', authenticateToken, async (req, res) => {
    try {
        // นับเฉพาะรายการที่ "เพื่อนพยาบาลตกลงกันแล้ว" และ "รอหัวหน้าอนุมัติ"
        const [swap] = await dbPool.query("SELECT COUNT(*) as count FROM Shift_Exchange WHERE status = 'accepted'");
        const [trade] = await dbPool.query("SELECT COUNT(*) as count FROM ShiftTransaction WHERE Status = 'Pending_HeadNurse'");

        res.json({ 
            success: true, 
            total: swap[0].count + trade[0].count, // ยอดรวมที่โชว์บนกระดิ่ง
            swapCount: swap[0].count, 
            tradeCount: trade[0].count 
        });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.get('/api/admin/get-settings', authenticateToken, async (req, res) => { try { const [rows] = await dbPool.query('SELECT * FROM SystemSettings'); const settings = {}; rows.forEach(r => { if (r.SettingKey === 'QuotaMorning') settings.morning = r.SettingValue; if (r.SettingKey === 'QuotaAfternoon') settings.afternoon = r.SettingValue; if (r.SettingKey === 'QuotaNight') settings.night = r.SettingValue; if (r.SettingKey === 'DeadlineDate') settings.deadline = r.SettingValue; }); res.json({ success: true, settings }); } catch (err) { res.status(500).json({ success: false }); } });
app.post('/api/admin/save-settings', authenticateToken, async (req, res) => {
    const { morning, afternoon, night, deadline } = req.body;

    // เตรียมข้อมูลเป็นคู่ Key-Value ให้ตรงกับ Database
    const settingsData = [
        { key: 'QuotaMorning', value: morning },
        { key: 'QuotaAfternoon', value: afternoon },
        { key: 'QuotaNight', value: night },
        { key: 'DeadlineDate', value: deadline }
    ];

    try {
        // วนลูปบันทึกทีละค่า
        for (const item of settingsData) {
            // เช็คว่าค่าไม่เป็น null/undefined ก่อนบันทึก
            if (item.value !== undefined && item.value !== null) {
                await dbPool.query(`
                    INSERT INTO SystemSettings (SettingKey, SettingValue) 
                    VALUES (?, ?) 
                    ON DUPLICATE KEY UPDATE SettingValue = VALUES(SettingValue)
                `, [item.key, item.value]);
            }
        }
        
        res.json({ success: true, message: "บันทึกข้อมูลเรียบร้อย" });

    } catch (err) {
        console.error("Save Settings Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// ==========================================
// 7. SCHEDULE & SWAP SYSTEM (Logic เดิม)
// ==========================================
app.post('/api/monthly-schedule', authenticateToken, async (req, res) => {
    const { userId, month, year } = req.body;
    if (!userId) return res.status(400).json({ message: "Data missing" });
    try {
        const sql = `SELECT DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as Nurse_Date, S.ShiftName, S.StartTime, S.EndTime, S.Shift_id, NS.ScheduleID FROM NurseSchedule NS JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE NS.UserID = ? AND MONTH(NS.Nurse_Date) = ? AND YEAR(NS.Nurse_Date) = ? ORDER BY NS.Nurse_Date ASC`;
        const [shifts] = await dbPool.query(sql, [userId, month, year]);
        res.json({ success: true, shifts });
    } catch (err) { res.status(500).json({ message: "Server Error" }); }
});

app.post('/api/submit-constraint', authenticateToken, async (req, res) => {
    const { userId, date, shiftId, reason } = req.body;
    try {
        const [exist] = await dbPool.query("SELECT * FROM NurseConstraint WHERE UserID = ? AND Constraint_Date = ? AND Shift_id = ?", [userId, date, shiftId]);
        if (exist.length > 0) return res.status(409).json({ message: "ส่งไปแล้ว" });
        await dbPool.query("INSERT INTO NurseConstraint (UserID, Constraint_Date, Shift_id, Reason) VALUES (?, ?, ?, ?)", [userId, date, shiftId, reason]);
        res.json({ success: true, message: "บันทึกสำเร็จ" });
    } catch (err) { res.status(500).json({ message: "Server Error" }); }
});

app.post('/api/posts/create', authenticateToken, async (req, res) => {
    try {
        const { userId, scheduleId, desiredDate, note } = req.body;
        if (!userId || !scheduleId) return res.status(400).json({ success: false, message: 'ข้อมูลไม่ครบถ้วน' });
        const [scheduleRows] = await dbPool.query(`SELECT UserID, Nurse_Date FROM NurseSchedule WHERE ScheduleID = ?`, [scheduleId]);
        if (scheduleRows.length === 0) return res.status(404).json({ success: false, message: 'ไม่พบข้อมูลตารางเวร' });
        const schedule = scheduleRows[0];
        if (schedule.UserID !== userId) return res.status(403).json({ success: false, message: 'คุณไม่ใช่เจ้าของเวรนี้' });
        const [duplicateRows] = await dbPool.query(`SELECT ExchangePostID FROM ExchangePost WHERE ScheduleID = ? AND Status = 'Open'`, [scheduleId]);
        if (duplicateRows.length > 0) return res.status(409).json({ success: false, message: 'เวรนี้มีประกาศเปิดอยู่แล้ว' });
        const sql = `INSERT INTO ExchangePost (UserID, ScheduleID, DesiredShiftDate, Message, Status, CreatedAt) VALUES (?, ?, ?, ?, 'Open', DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        const [result] = await dbPool.query(sql, [userId, scheduleId, desiredDate || null, note || null]);
        res.status(201).json({ success: true, message: 'สร้างประกาศสำเร็จ', postId: result.insertId });
    } catch (err) { console.error('Create Exchange Post Error:', err); res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดของระบบ' }); }
});

app.post('/api/full-schedule', authenticateToken, async (req, res) => {
    try {
        const { month, year } = req.body;
        if (!month || !year) return res.status(400).json({ success: false, message: "กรุณาระบุเดือนและปี" });
        const sql = `SELECT NS.ScheduleID, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as Nurse_Date, U.UserID, U.FirstName, U.LastName, U.ProfileImage, U.RoleID, S.Shift_id, S.ShiftName, S.StartTime, S.EndTime FROM NurseSchedule NS JOIN User U ON NS.UserID = U.UserID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE MONTH(NS.Nurse_Date) = ? AND YEAR(NS.Nurse_Date) = ? ORDER BY NS.Nurse_Date ASC, S.StartTime ASC, U.FirstName ASC`;
        const [shifts] = await dbPool.query(sql, [month, year]);
        res.json({ success: true, shifts: shifts });
    } catch (err) { console.error("Full Schedule Error:", err); res.status(500).json({ success: false, message: "Server Error: " + err.message }); }
});

app.post('/api/swaps/search', authenticateToken, async (req, res) => {
    const { date, shiftId, requesterId } = req.body;
    
    if (!date) {
        return res.status(400).json({ success: false, message: "กรุณาระบุวันที่ต้องการค้นหา" });
    }

    try {
        // SQL ใหม่: 
        // 1. เริ่มจาก NurseSchedule (NS) เพื่อดึงทุกคนที่มีเวร
        // 2. JOIN User และ Shift เพื่อเอาชื่อและเวลากะ
        // 3. LEFT JOIN ExchangePost (EP) เพื่อดูว่าเขามีประกาศ "Open" อยู่ไหม (ถ้าไม่มีค่าจะเป็น null)
        let sql = `
            SELECT 
                U.UserID, 
                U.FirstName, 
                U.LastName, 
                U.ProfileImage, 
                NS.ScheduleID, 
                DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as Nurse_Date, 
                S.ShiftName, 
                S.Shift_id,
                EP.ExchangePostID, 
                EP.Message,
                CASE 
                    WHEN EP.ExchangePostID IS NOT NULL THEN 'Posted' 
                    ELSE 'Normal' 
                END as SwapStatus
            FROM NurseSchedule NS 
            JOIN User U ON NS.UserID = U.UserID 
            JOIN Shift S ON NS.Shift_id = S.Shift_id 
            LEFT JOIN ExchangePost EP ON NS.ScheduleID = EP.ScheduleID AND EP.Status = 'Open'
            WHERE NS.Nurse_Date = ? AND U.UserID != ?
        `;

        const params = [date, requesterId];

        // ถ้ามีการระบุ shiftId ให้กรองเฉพาะกะที่ต้องการด้วย
        if (shiftId) { 
            sql += " AND S.Shift_id = ? "; 
            params.push(shiftId); 
        }

        // เรียงลำดับ: คนที่มีประกาศขึ้นก่อน, ตามด้วยชื่อ
        sql += " ORDER BY SwapStatus DESC, U.FirstName ASC";

        const [results] = await dbPool.query(sql, params);
        res.json({ success: true, results });

    } catch (err) { 
        console.error("Search Swap Error:", err); 
        res.status(500).json({ success: false, message: "DB Error" }); 
    }
});

app.post('/api/swaps/send-request', authenticateToken, async (req, res) => {
    try {
        // รับค่า targetScheduleId (เวรเพื่อน) เพิ่มเข้ามา
        const { requesterId, requesterScheduleId, postId, targetScheduleId, reason } = req.body;

        // 1. เช็คข้อมูลฝั่งคนขอ (ต้องมีเสมอ)
        if (!requesterId || !requesterScheduleId) {
            return res.status(400).json({ success: false, message: 'ข้อมูลฝั่งคนขอไม่ครบถ้วน (requesterId หรือ requesterScheduleId)' });
        }

        let responderId = null;
        let responderScheduleId = null;

        // 2. กรณี A: แลกผ่านประกาศ (มี postId) - แบบเดิม
        if (postId) {
            const [postData] = await dbPool.query("SELECT UserID, ScheduleID FROM ExchangePost WHERE ExchangePostID = ?", [postId]);
            if (postData.length === 0) return res.status(404).json({ success: false, message: 'ไม่พบประกาศนี้' });
            
            responderId = postData[0].UserID;
            responderScheduleId = postData[0].ScheduleID;
        } 
        // 3. กรณี B: แลกตรง (ไม่มี postId) - แบบใหม่ ⭐️
        else if (targetScheduleId) {
            // ไปค้นหาว่าเวรเป้าหมายนี้ เป็นของใคร?
            const [scheduleData] = await dbPool.query("SELECT UserID, ScheduleID FROM NurseSchedule WHERE ScheduleID = ?", [targetScheduleId]);
            if (scheduleData.length === 0) return res.status(404).json({ success: false, message: 'ไม่พบเวรที่ต้องการแลก' });

            responderId = scheduleData[0].UserID;
            responderScheduleId = scheduleData[0].ScheduleID;

            // ป้องกันการแลกเวรกับตัวเอง
            if (responderId == requesterId) {
                return res.status(400).json({ success: false, message: 'คุณจะแลกเวรกับตัวเองไม่ได้' });
            }
        } 
        else {
            // ถ้าไม่ส่งทั้ง postId และ targetScheduleId มาเลย
            return res.status(400).json({ success: false, message: 'ระบุข้อมูลไม่ครบ (ต้องมี postId หรือ targetScheduleId)' });
        }

        // 4. เช็คว่าเคยขอไปหรือยัง (Logic เดิม)
        const [existing] = await dbPool.query(
            "SELECT exchange_id FROM Shift_Exchange WHERE requester_schedule_id = ? AND responder_schedule_id = ? AND status = 'pending'", 
            [requesterScheduleId, responderScheduleId]
        );
        if (existing.length > 0) return res.status(400).json({ success: false, message: 'คำขอนี้รอการอนุมัติอยู่แล้ว' });

        // 5. บันทึกลง Database
        const sql = `INSERT INTO Shift_Exchange (requester_id, requester_schedule_id, responder_id, responder_schedule_id, status, reason, created_at) VALUES (?, ?, ?, ?, 'pending', ?, DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        await dbPool.query(sql, [requesterId, requesterScheduleId, responderId, responderScheduleId, reason]);

        res.json({ success: true, message: 'ส่งคำขอเรียบร้อย รอเพื่อนหรือหัวหน้าอนุมัติ' });

    } catch (err) { 
        console.error(err); 
        res.status(500).json({ success: false, message: "Server Error: " + err.message }); 
    }
});
// =======================================================
// [เพิ่มใหม่] API ให้เพื่อนกดตอบรับ/ปฏิเสธ คำขอแลกเวร
// =======================================================
app.post('/api/swaps/respond', authenticateToken, async (req, res) => {
    const { swapId, action, responderId } = req.body;

    if (!swapId || !action || !responderId) return res.status(400).json({ success: false, message: "ข้อมูลไม่ครบ" });

    try {
        const [check] = await dbPool.query(
            "SELECT * FROM Shift_Exchange WHERE exchange_id = ? AND responder_id = ? AND status = 'pending'", 
            [swapId, responderId]
        );

        if (check.length === 0) return res.status(403).json({ success: false, message: "ไม่มีสิทธิ์ดำเนินการ" });

        if (action === 'approve') {
            // ✅ เปลี่ยนเป็น 'accepted' (เพื่อให้ตรงกับ ENUM ใน DB)
            await dbPool.query("UPDATE Shift_Exchange SET status = 'accepted' WHERE exchange_id = ?", [swapId]);
            res.json({ success: true, message: "ยอมรับคำขอแล้ว รอหัวหน้าอนุมัติ" });
        } else if (action === 'reject') {
            await dbPool.query("UPDATE Shift_Exchange SET status = 'rejected' WHERE exchange_id = ?", [swapId]);
            res.json({ success: true, message: "ปฏิเสธคำขอเรียบร้อย" });
        } else {
            res.status(400).json({ success: false, message: "Action ไม่ถูกต้อง" });
        }
    } catch (err) {
        console.error("Swap Respond Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

app.get('/api/notifications/all/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const userRole = req.user.roleId || 2; 

    try {
        let buyReqs = [], swapReqs = [];
        let paramsBuy = [], paramsSwap = [];

        // --- 1. ดึงรายการคำขอที่รอการตอบรับ (Pending Requests) ---
        if (userRole === 1) { // หัวหน้าพยาบาล
            // ดูรายการที่เพื่อนพยาบาลตกลงกันแล้ว รอหัวหน้าอนุมัติ
            const sqlBuyAdmin = `
                SELECT ST.TransactionID as id, 'buy' as type, 
                DATE_FORMAT(DATE_ADD(ST.CreatedAt, INTERVAL 7 HOUR), '%Y-%m-%dT%H:%i:%s') as created_at, 
                ST.Price as info, Buyer.FirstName, Buyer.LastName, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate 
                FROM ShiftTransaction ST 
                JOIN User Buyer ON ST.BuyerID = Buyer.UserID 
                JOIN NurseSchedule NS ON ST.ScheduleID = NS.ScheduleID 
                JOIN Shift S ON NS.Shift_id = S.Shift_id 
                WHERE ST.Status = 'Pending_HeadNurse'
            `;
            const sqlSwapAdmin = `
                SELECT SE.exchange_id as id, 'swap' as type, 
                DATE_FORMAT(DATE_ADD(SE.created_at, INTERVAL 7 HOUR), '%Y-%m-%dT%H:%i:%s') as created_at, 
                SE.reason as info, Requester.FirstName, Requester.LastName, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate 
                FROM Shift_Exchange SE 
                JOIN User Requester ON SE.requester_id = Requester.UserID 
                JOIN NurseSchedule NS ON SE.responder_schedule_id = NS.ScheduleID 
                JOIN Shift S ON NS.Shift_id = S.Shift_id 
                WHERE SE.status = 'accepted' 
            `;
            const [b] = await dbPool.query(sqlBuyAdmin); buyReqs = b;
            const [s] = await dbPool.query(sqlSwapAdmin); swapReqs = s;
        } else { // พยาบาลทั่วไป
            // ดูรายการที่มีคนส่งมาขอแลก/ซื้อกับเรา
            const sqlBuyNurse = `
                SELECT ST.TransactionID as id, 'buy' as type, 
                DATE_FORMAT(DATE_ADD(ST.CreatedAt, INTERVAL 7 HOUR), '%Y-%m-%dT%H:%i:%s') as created_at, 
                ST.Price as info, Buyer.FirstName, Buyer.LastName, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate 
                FROM ShiftTransaction ST 
                JOIN User Buyer ON ST.BuyerID = Buyer.UserID 
                JOIN NurseSchedule NS ON ST.ScheduleID = NS.ScheduleID 
                JOIN Shift S ON NS.Shift_id = S.Shift_id 
                WHERE ST.SellerID = ? AND ST.Status = 'Pending_Seller'
            `;
            const sqlSwapNurse = `
                SELECT SE.exchange_id as id, 'swap' as type, 
                DATE_FORMAT(DATE_ADD(SE.created_at, INTERVAL 7 HOUR), '%Y-%m-%dT%H:%i:%s') as created_at, 
                SE.reason as info, Requester.FirstName, Requester.LastName, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate 
                FROM Shift_Exchange SE 
                JOIN User Requester ON SE.requester_id = Requester.UserID 
                JOIN NurseSchedule NS ON SE.responder_schedule_id = NS.ScheduleID 
                JOIN Shift S ON NS.Shift_id = S.Shift_id 
                WHERE SE.responder_id = ? AND SE.status = 'pending'
            `;
            const [b] = await dbPool.query(sqlBuyNurse, [userId]); buyReqs = b;
            const [s] = await dbPool.query(sqlSwapNurse, [userId]); swapReqs = s;
        }

        // --- 2. ดึงรายการแจ้งเตือนจากตาราง Notifications (ประวัติที่หัวหน้าอนุมัติแล้ว) ---
        const sqlSystem = `
            SELECT 
                NotiID as id, 
                'system' as type, 
                DATE_FORMAT(CreatedAt, '%Y-%m-%dT%H:%i:%s') as created_at,
                Message as info,
                'ระบบ' as FirstName, 
                Title as LastName, 
                RelatedShift as ShiftName,    -- ดึงชื่อกะที่บันทึกไว้
                RelatedDate as ShiftDate       -- ดึงวันที่เวรที่เกี่ยวข้อง
            FROM Notifications 
            WHERE UserID = ? 
            ORDER BY CreatedAt DESC LIMIT 30
        `;
        const [systemNotis] = await dbPool.query(sqlSystem, [userId]);

        // --- 3. รวมแจ้งเตือนทั้งหมดและเรียงลำดับเวลาใหม่ ---
        const allNotis = [...buyReqs, ...swapReqs, ...systemNotis];
        allNotis.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        
        res.json({ success: true, notifications: allNotis });

    } catch (err) { 
        console.error("Noti Error:", err); 
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});
app.get('/api/admin/swaps/pending', authenticateToken, async (req, res) => {
    try {
        const sql = `SELECT SE.exchange_id, SE.reason, SE.created_at, ReqU.FirstName AS ReqName, ReqU.LastName AS ReqLast, ReqShift.ShiftName AS ReqShift, ReqNS.Nurse_Date AS ReqDate, ResU.FirstName AS ResName, ResU.LastName AS ResLast, ResShift.ShiftName AS ResShift, ResNS.Nurse_Date AS ResDate FROM Shift_Exchange SE JOIN User ReqU ON SE.requester_id = ReqU.UserID JOIN NurseSchedule ReqNS ON SE.requester_schedule_id = ReqNS.ScheduleID JOIN Shift ReqShift ON ReqNS.Shift_id = ReqShift.Shift_id JOIN User ResU ON SE.responder_id = ResU.UserID JOIN NurseSchedule ResNS ON SE.responder_schedule_id = ResNS.ScheduleID JOIN Shift ResShift ON ResNS.Shift_id = ResShift.Shift_id WHERE SE.status = 'pending' ORDER BY SE.created_at ASC`;
        const [results] = await dbPool.query(sql);
        res.json({ success: true, results });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "DB Error" }); }
});

app.post('/api/admin/swaps/action', authenticateToken, async (req, res) => {
    const { swapId, action, adminId } = req.body;
    const connection = await dbPool.getConnection();

    try {
        await connection.beginTransaction();

        // 1. ดึงข้อมูลรายการแลกเวร (ใช้ชื่อคอลัมน์ที่ถูกต้องตามตาราง Shift_Exchange ของคุณ)
        const [swaps] = await connection.query(`
            SELECT se.*, 
                   ns1.Nurse_Date as Date1, ns1.Shift_id as Shift1,
                   ns2.Nurse_Date as Date2, ns2.Shift_id as Shift2
            FROM Shift_Exchange se
            JOIN NurseSchedule ns1 ON se.requester_schedule_id = ns1.ScheduleID
            JOIN NurseSchedule ns2 ON se.responder_schedule_id = ns2.ScheduleID
            WHERE se.exchange_id = ? FOR UPDATE`, [swapId]);

        if (swaps.length === 0) throw new Error("ไม่พบรายการแลกเวร");
        const swap = swaps[0];

        const createNoti = `INSERT INTO Notifications (UserID, Title, Message, Type, RelatedDate, RelatedShift, CreatedAt) 
                            VALUES (?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 HOUR))`;

        if (action === 'approve') {
            // 2. สลับเจ้าของเวรใน NurseSchedule จริงๆ
            await connection.query("UPDATE NurseSchedule SET UserID = ? WHERE ScheduleID = ?", [swap.responder_id, swap.requester_schedule_id]);
            await connection.query("UPDATE NurseSchedule SET UserID = ? WHERE ScheduleID = ?", [swap.requester_id, swap.responder_schedule_id]);

            // 3. อัปเดตสถานะเป็น 'approved'
            await connection.query("UPDATE Shift_Exchange SET status = 'approved', approved_by = ? WHERE exchange_id = ?", [adminId, swapId]);

            // 4. บันทึกสถิติ ExchangesMade (จำนวนครั้งที่แลกเวร)
            const statsSql = `INSERT INTO NurseStatistics (UserID, Year, Month, ExchangesMade, TotalShifts, CreatedAt) 
                              VALUES (?, YEAR(NOW()), MONTH(NOW()), 1, 0, DATE_ADD(NOW(), INTERVAL 7 HOUR)) 
                              ON DUPLICATE KEY UPDATE ExchangesMade = ExchangesMade + 1`;
            
            await connection.query(statsSql, [swap.requester_id]);
            await connection.query(statsSql, [swap.responder_id]);

            // 5. แจ้งเตือนพยาบาลทั้งคู่ (แบบอ่านอย่างเดียว - system)
            const msg = `หัวหน้าอนุมัติการแลกเวรวันที่ ${swap.Date1} และ ${swap.Date2} เรียบร้อยแล้ว`;
            await connection.query(createNoti, [swap.requester_id, 'การแลกเวรสำเร็จ', msg, 'system', swap.Date1, 'สลับเวรสำเร็จ']);
            await connection.query(createNoti, [swap.responder_id, 'การแลกเวรสำเร็จ', msg, 'system', swap.Date2, 'สลับเวรสำเร็จ']);

        } else if (action === 'reject') {
            await connection.query("UPDATE Shift_Exchange SET status = 'rejected', approvedby = ? WHERE exchange_id = ?", [adminId, swapId]);
            await connection.query(createNoti, [swap.requester_id, 'การแลกเวรถูกปฏิเสธ', 'หัวหน้าไม่อนุมัติการแลกเวรของคุณ', 'system', swap.Date1, 'แลกเวรไม่สำเร็จ']);
        }

        await connection.commit();
        res.json({ success: true, message: action === 'approve' ? "อนุมัติเรียบร้อย" : "ปฏิเสธเรียบร้อย" });
    } catch (err) {
        await connection.rollback();
        res.status(500).json({ success: false, message: err.message });
    } finally { connection.release(); }
});
// ✅ แก้ไข API ดึงประวัติการแลกเวร
app.get('/api/swaps/history/:userId', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        // ปรับ SQL ให้ Join กับตาราง NurseSchedule เพื่อเอาวันที่เวรมาโชว์ด้วย
        const sql = `
            SELECT 
                SE.exchange_id, 
                SE.status, 
                DATE_FORMAT(DATE_ADD(SE.created_at, INTERVAL 7 HOUR), '%Y-%m-%dT%H:%i:%s') as created_at, 
                SE.reason, 
                ResU.FirstName AS PartnerName, 
                ResU.LastName AS PartnerLastName,
                DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate,
                S.ShiftName,
                CASE 
                    WHEN SE.requester_id = ? THEN 'Sent Request' 
                    ELSE 'Incoming Request' 
                END as Direction 
            FROM Shift_Exchange SE 
            JOIN User ResU ON (SE.responder_id = ResU.UserID OR SE.requester_id = ResU.UserID)
            JOIN NurseSchedule NS ON SE.responder_schedule_id = NS.ScheduleID
            JOIN Shift S ON NS.Shift_id = S.Shift_id
            WHERE (SE.requester_id = ? OR SE.responder_id = ?) 
              AND ResU.UserID != ? 
            ORDER BY SE.created_at DESC`;

        const [results] = await dbPool.query(sql, [userId, userId, userId, userId]);
        res.json({ success: true, results });
    } catch (err) { 
        console.error("History Error:", err); 
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});

// ✅ แก้ไข API ดึงแจ้งเตือนรวม
app.get('/api/notifications/all/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const userRole = req.user.roleId || 2; 

    try {
        let buyReqs = [], swapReqs = [];

        // ส่วนที่ 1: ดึง Request เดิม (Swap/Buy) -- Logic เดิมของคุณ
        if (userRole === 1) { // หัวหน้า
             // SQL เดิมของหัวหน้า (หา Pending_HeadNurse / pending_head_nurse)
             // ... ใส่โค้ดเดิมตรงนี้ ...
        } else { // พยาบาลทั่วไป
             const sqlBuy = `SELECT ST.TransactionID as id, 'buy' as type, DATE_FORMAT(DATE_ADD(ST.CreatedAt, INTERVAL 7 HOUR), '%Y-%m-%dT%H:%i:%s') as created_at, ST.Price as info, Buyer.FirstName, Buyer.LastName, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate FROM ShiftTransaction ST JOIN User Buyer ON ST.BuyerID = Buyer.UserID JOIN NurseSchedule NS ON ST.ScheduleID = NS.ScheduleID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE ST.SellerID = ? AND ST.Status = 'Pending_Seller'`;
             const sqlSwap = `SELECT SE.exchange_id as id, 'swap' as type, DATE_FORMAT(DATE_ADD(SE.created_at, INTERVAL 7 HOUR), '%Y-%m-%dT%H:%i:%s') as created_at, se.reason as info, Requester.FirstName, Requester.LastName, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate FROM Shift_Exchange SE JOIN User Requester ON SE.requester_id = Requester.UserID JOIN NurseSchedule NS ON SE.responder_schedule_id = NS.ScheduleID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE SE.responder_id = ? AND SE.status = 'pending'`;

             const [r1] = await dbPool.query(sqlBuy, [userId]);
             buyReqs = r1;
             const [r2] = await dbPool.query(sqlSwap, [userId]);
             swapReqs = r2;
        }

        // ✅ ส่วนที่ 2 (เพิ่มใหม่): ดึงจากตาราง Notifications
        // Map ชื่อ Field ให้ตรงกับที่ Frontend ใช้ (FirstName, LastName, info)
        const sqlSystem = `
                SELECT 
                    NotiID as id, 
                    'system' as type, 
                    DATE_FORMAT(CreatedAt, '%Y-%m-%dT%H:%i:%s') as created_at,
                    Message as info,
                    'ระบบ' as FirstName, 
                    Title as LastName, 
                    RelatedShift as ShiftName,
                    RelatedDate as ShiftDate 
                FROM Notifications 
                WHERE UserID = ? 
                ORDER BY CreatedAt DESC LIMIT 30
            `;
        const [systemNotis] = await dbPool.query(sqlSystem, [userId]);

        // 3. รวมร่างแล้วส่งกลับ
        const allNotis = [...buyReqs, ...swapReqs, ...systemNotis];
        
        // เรียงตามเวลาล่าสุด
        allNotis.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        
        res.json({ success: true, notifications: allNotis });

    } catch (err) { 
        console.error("Noti Error:", err); 
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});
app.get('/api/posts/user/:userId', authenticateToken, async (req, res) => {
    try {
        const sql = `SELECT EP.ExchangePostID as PostID, EP.DesiredShiftDate as DesiredDate, EP.Message as Note, EP.CreatedAt as Created_At, S.ShiftName, NS.Nurse_Date FROM ExchangePost EP JOIN NurseSchedule NS ON EP.ScheduleID = NS.ScheduleID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE EP.UserID = ? AND EP.Status = 'Open' ORDER BY EP.CreatedAt DESC`;
        const [results] = await dbPool.query(sql, [req.params.userId]);
        res.json({ success: true, results });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "DB Error" }); }
});

app.delete('/api/posts/delete/:postId', authenticateToken, async (req, res) => {
    try {
        await dbPool.query("DELETE FROM ExchangePost WHERE ExchangePostID = ?", [req.params.postId]);
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ success: false }); }
});

app.get('/api/schedule/my-future-shifts/:userId', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        if (!userId) return res.status(400).json({ success: false, message: "UserID required" });
        const sql = `SELECT NS.ScheduleID, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as Nurse_Date, S.ShiftName, S.Shift_id FROM NurseSchedule NS JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE NS.UserID = ? AND NS.Nurse_Date >= CURRENT_DATE() ORDER BY NS.Nurse_Date ASC`;
        const [results] = await dbPool.query(sql, [userId]);
        res.json({ success: true, results: results });
    } catch (err) { console.error("Error fetching future shifts:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

// ==========================================
// 8. STATISTICS & MARKET SYSTEM (Logic เดิม)
// ==========================================
app.post('/api/my-stats', authenticateToken, async (req, res) => {
    const { userId, year } = req.body;
    if (!userId || !year) return res.status(400).json({ success: false, message: 'ข้อมูลไม่ครบถ้วน' });
    try {
        const sqlSummary = `SELECT COUNT(*) as total_shifts, SUM(CASE WHEN S.ShiftName NOT LIKE '%ลา%' THEN 8 ELSE 0 END) as total_hours, SUM(CASE WHEN S.ShiftName LIKE '%ลา%' THEN 1 ELSE 0 END) as total_leaves FROM NurseSchedule NS JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE NS.UserID = ? AND YEAR(NS.Nurse_Date) = ?`;
        const sqlMonthly = `SELECT MONTH(NS.Nurse_Date) as month, COUNT(*) as total, SUM(CASE WHEN S.ShiftName LIKE '%เช้า%' THEN 1 ELSE 0 END) as morning, SUM(CASE WHEN S.ShiftName LIKE '%บ่าย%' THEN 1 ELSE 0 END) as afternoon, SUM(CASE WHEN S.ShiftName LIKE '%ดึก%' THEN 1 ELSE 0 END) as night FROM NurseSchedule NS JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE NS.UserID = ? AND YEAR(NS.Nurse_Date) = ? GROUP BY MONTH(NS.Nurse_Date) ORDER BY month ASC`;
        const sqlTradeStats = `SELECT SUM(ExchangesMade) as total_swaps, SUM(ShiftsBought + ShiftsSold) as total_trades FROM NurseStatistics WHERE UserID = ? AND Year = ?`;
        const [summaryRes, monthlyRes, tradeRes] = await Promise.all([
            dbPool.query(sqlSummary, [userId, year]),
            dbPool.query(sqlMonthly, [userId, year]),
            dbPool.query(sqlTradeStats, [userId, year])
        ]);
        const summary = summaryRes[0][0];
        const trades = tradeRes[0][0] || {};
        const monthlyDetails = [];
        for (let m = 1; m <= 12; m++) {
            const found = monthlyRes[0].find(row => row.month === m);
            monthlyDetails.push({ month: m, total: found ? found.total : 0, morning: found ? found.morning : 0, afternoon: found ? found.afternoon : 0, night: found ? found.night : 0 });
        }
        res.json({ success: true, data: { year: parseInt(year), totalShifts: summary.total_shifts || 0, totalHours: summary.total_hours || 0, totalLeaves: summary.total_leaves || 0, totalSwaps: trades.total_swaps || 0, totalTrades: trades.total_trades || 0, monthlyDetails: monthlyDetails } });
    } catch (err) { console.error("Stats API Error:", err); res.status(500).json({ success: false, message: "Error" }); }
});

app.post('/api/posts/update', authenticateToken, async (req, res) => {
    try {
        const { postId, desiredDate, note } = req.body;
        if (!postId) return res.status(400).json({ success: false, message: 'ไม่พบรหัสโพสต์' });
        const dateValue = (desiredDate && desiredDate !== "") ? desiredDate : null;
        const sql = `UPDATE ExchangePost SET DesiredShiftDate = ?, Message = ? WHERE ExchangePostID = ?`;
        const [result] = await dbPool.query(sql, [dateValue, note, postId]);
        if (result.affectedRows === 0) return res.status(404).json({ success: false, message: 'ไม่พบโพสต์' });
        res.json({ success: true, message: 'บันทึกการเปลี่ยนแปลงเรียบร้อย' });
    } catch (err) { console.error("Update Post Error:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

app.get('/api/swaps/incoming/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const sql = `SELECT se.exchange_id AS SwapID, se.requester_id AS RequesterID, CONCAT(u.FirstName, ' ', u.LastName) AS RequesterName, u.ProfileImage, se.requester_schedule_id AS RequesterScheduleID, s_req.Nurse_Date AS RequesterDate, sh_req.ShiftName AS RequesterShift, se.responder_schedule_id AS TargetScheduleID, s_target.Nurse_Date AS TargetDate, sh_target.ShiftName AS TargetShift, se.status AS Status, se.created_at AS Created_At FROM Shift_Exchange se JOIN User u ON se.requester_id = u.UserID JOIN NurseSchedule s_req ON se.requester_schedule_id = s_req.ScheduleID JOIN Shift sh_req ON s_req.Shift_id = sh_req.Shift_id JOIN NurseSchedule s_target ON se.responder_schedule_id = s_target.ScheduleID JOIN Shift sh_target ON s_target.Shift_id = sh_target.Shift_id WHERE se.responder_id = ? AND se.status = 'pending' ORDER BY se.created_at DESC`;
    try {
        const [results] = await dbPool.query(sql, [userId]);
        res.json({ success: true, results: results });
    } catch (err) { console.error("Incoming Swaps Error:", err); res.status(500).json({ success: false, message: 'Server Error' }); }
});

app.post('/api/sell-shift', authenticateToken, async (req, res) => {
    const { userId, scheduleId, price, message } = req.body;
    if (!userId || !scheduleId || !price) return res.status(400).json({ success: false, message: 'ข้อมูลไม่ครบ' });
    try {
        const [existingPost] = await dbPool.query("SELECT PostSellID FROM PostSell WHERE ScheduleID = ? AND Status = 'Open'", [scheduleId]);
        if (existingPost.length > 0) return res.status(409).json({ success: false, message: 'เวรนี้ถูกลงประกาศขายอยู่แล้ว' });
        const sql = `INSERT INTO PostSell (UserID, ScheduleID, Price, Message, Status, CreatedAT) VALUES (?, ?, ?, ?, 'Open', DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        const [result] = await dbPool.query(sql, [userId, scheduleId, price, message]);
        res.json({ success: true, message: 'ประกาศขายเวรสำเร็จ', id: result.insertId });
    } catch (err) { console.error("Sell Shift Error:", err); res.status(500).json({ success: false, message: 'Server Error' }); }
});

app.get('/api/market/shifts', authenticateToken, async (req, res) => {
    const filterType = req.query.type;
    const currentUserId = req.query.userId;
    try {
        let sql = `SELECT PS.PostSellID, PS.Price, PS.Message as ConditionText, PS.CreatedAT, PS.UserID as SellerID, U.FirstName, U.LastName, U.ProfileImage, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as Nurse_Date, S.ShiftName, S.StartTime, S.EndTime, CASE WHEN PS.Price LIKE '%ด่วน%' THEN 1 ELSE 0 END as IsUrgent FROM PostSell PS JOIN NurseSchedule NS ON PS.ScheduleID = NS.ScheduleID JOIN User U ON PS.UserID = U.UserID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE PS.Status = 'Open' AND PS.UserID != ? `;
        if (filterType && filterType !== 'all') {
            let likeTerm = filterType === 'morning' ? '%เช้า%' : filterType === 'afternoon' ? '%บ่าย%' : '%ดึก%';
            sql += ` AND S.ShiftName LIKE '${likeTerm}'`;
        }
        sql += ` ORDER BY IsUrgent DESC, NS.Nurse_Date ASC`;
        const [results] = await dbPool.query(sql, [currentUserId]);
        const formattedResults = results.map(row => ({ id: row.PostSellID, user_name: `${row.FirstName} ${row.LastName}`, department: 'พยาบาลวิชาชีพ', shift_date: row.Nurse_Date, shift_time_label: row.ShiftName, condition: row.Price, is_urgent: row.IsUrgent === 1, created_at: row.CreatedAT }));
        res.json(formattedResults);
    } catch (err) { console.error("Market Fetch Error:", err); res.status(500).json({ success: false, message: "DB Error" }); }
});

app.post('/api/market/request-trade', authenticateToken, async (req, res) => {
    const { userId, sellId } = req.body; 
    try {
        const [posts] = await dbPool.query("SELECT UserID, ScheduleID, Price FROM PostSell WHERE PostSellID = ?", [sellId]);
        if (posts.length === 0) return res.status(404).json({ success: false, message: "ไม่พบประกาศ" });
        const post = posts[0];
        if (post.UserID == userId) return res.status(400).json({ success: false, message: "ไม่สามารถขอซื้อเวรตัวเองได้" });
        const sql = `INSERT INTO ShiftTransaction (PostSellID, SellerID, BuyerID, ScheduleID, Price, Status, CreatedAt) VALUES (?, ?, ?, ?, ?, 'Pending_Seller', DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        await dbPool.query(sql, [sellId, post.UserID, userId, post.ScheduleID, post.Price]);
        res.json({ success: true, message: 'ส่งคำขอสำเร็จ รอเจ้าของเวรตอบรับ' });
    } catch (err) { console.error("Trade Request Error:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

app.get('/api/market/my-requests/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const sql = `SELECT ST.TransactionID, ST.Status, ST.CreatedAt as RequestDate, Seller.FirstName as OwnerName, NS.Nurse_Date, S.ShiftName FROM ShiftTransaction ST JOIN User Seller ON ST.SellerID = Seller.UserID JOIN NurseSchedule NS ON ST.ScheduleID = NS.ScheduleID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE ST.BuyerID = ? ORDER BY ST.TransactionID DESC`;
        const [results] = await dbPool.query(sql, [userId]);
        const formatted = results.map(row => ({ id: row.TransactionID, status: row.Status.toLowerCase(), created_at: row.RequestDate, title: `ขอซื้อเวร ${row.OwnerName}`, shift_date: row.Nurse_Date, note: row.ShiftName }));
        res.json(formatted);
    } catch (err) { console.error("My Status Error:", err); res.status(500).json({ success: false }); }
});

app.get('/api/market/my-active-posts/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const sql = `SELECT PS.PostSellID, PS.Price, PS.Message, PS.CreatedAT, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as Nurse_Date, S.ShiftName FROM PostSell PS JOIN NurseSchedule NS ON PS.ScheduleID = NS.ScheduleID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE PS.UserID = ? AND PS.Status = 'Open' ORDER BY PS.CreatedAT DESC`;
        const [results] = await dbPool.query(sql, [userId]);
        const formatted = results.map(row => ({ id: row.PostSellID, price: row.Price, message: row.Message, shift_date: row.Nurse_Date, shift_label: row.ShiftName, created_at: row.CreatedAT }));
        res.json({ success: true, posts: formatted });
    } catch (err) { res.status(500).json({ success: false, message: "DB Error" }); }
});

app.post('/api/market/delete-post', authenticateToken, async (req, res) => {
    const { postId } = req.body;
    try {
        const [check] = await dbPool.query("SELECT COUNT(*) as count FROM ShiftTransaction WHERE PostSellID = ?", [postId]);
        if (check[0].count > 0) return res.status(400).json({ success: false, message: "มีผู้กดขอซื้อรายการนี้อยู่ ลบไม่ได้" });
        await dbPool.query("DELETE FROM PostSell WHERE PostSellID = ?", [postId]);
        res.json({ success: true, message: "ลบประกาศเรียบร้อยแล้ว" });
    } catch (err) { console.error("Delete Error:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

app.post('/api/market/edit-post', authenticateToken, async (req, res) => {
    const { postId, price, message } = req.body;
    if (!postId || !price) return res.status(400).json({ success: false, message: "ข้อมูลไม่ครบ" });
    try {
        const [check] = await dbPool.query("SELECT COUNT(*) as count FROM ShiftTransaction WHERE PostSellID = ? AND Status IN ('Pending_Seller', 'Pending_HeadNurse', 'Completed')", [postId]);
        if (check[0].count > 0) return res.status(400).json({ success: false, message: "แก้ไขไม่ได้: มีคนทำรายการซื้อขายค้างอยู่" });
        await dbPool.query("UPDATE PostSell SET Price = ?, Message = ? WHERE PostSellID = ?", [price, message, postId]);
        res.json({ success: true, message: "แก้ไขข้อมูลสำเร็จ" });
    } catch (err) { console.error("Edit Post Error:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

app.get('/api/my-sellable-shifts/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    try {
        const sql = `SELECT NS.ScheduleID, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as Nurse_Date, S.ShiftName, S.StartTime, S.EndTime FROM NurseSchedule NS JOIN Shift S ON NS.Shift_id = S.Shift_id LEFT JOIN PostSell PS ON NS.ScheduleID = PS.ScheduleID AND PS.Status = 'Open' WHERE NS.UserID = ? AND NS.Nurse_Date >= CURRENT_DATE() AND PS.PostSellID IS NULL ORDER BY NS.Nurse_Date ASC`;
        const [results] = await dbPool.query(sql, [userId]);
        const shifts = results.map(row => ({ id: row.ScheduleID, label: `${row.Nurse_Date} | ${row.ShiftName} (${row.StartTime.slice(0,5)}-${row.EndTime.slice(0,5)})` }));
        res.json({ success: true, shifts });
    } catch (err) { console.error("Fetch Sellable Shifts Error:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

app.get('/api/market/incoming-requests/:sellerId', authenticateToken, async (req, res) => {
    const sellerId = req.params.sellerId;
    try {
        const sql = `SELECT ST.TransactionID, ST.Price, ST.Status, ST.CreatedAt, Buyer.FirstName, Buyer.LastName, Buyer.ProfileImage, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate FROM ShiftTransaction ST JOIN User Buyer ON ST.BuyerID = Buyer.UserID JOIN NurseSchedule NS ON ST.ScheduleID = NS.ScheduleID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE ST.SellerID = ? AND ST.Status = 'Pending_Seller' ORDER BY ST.TransactionID DESC`;
        const [results] = await dbPool.query(sql, [sellerId]);
        res.json({ success: true, requests: results });
    } catch (err) { console.error("Incoming Request Error:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

app.post('/api/market/seller-respond', authenticateToken, async (req, res) => {
    const { transactionId, action } = req.body; 
    try {
        let newStatus = action === 'approve' ? 'Pending_HeadNurse' : action === 'reject' ? 'Rejected' : null;
        if (!newStatus) return res.status(400).json({ success: false, message: "Action Invalid" });
        await dbPool.query("UPDATE ShiftTransaction SET Status = ? WHERE TransactionID = ?", [newStatus, transactionId]);
        res.json({ success: true, message: action === 'approve' ? 'ยืนยันแล้ว รอหัวหน้าอนุมัติ' : 'ปฏิเสธแล้ว' });
    } catch (err) { console.error("Seller Respond Error:", err); res.status(500).json({ success: false, message: "Server Error" }); }
});

app.get('/api/admin/market/pending', authenticateToken, async (req, res) => {
    try {
        const sql = `SELECT ST.TransactionID, ST.Price, ST.CreatedAt, Seller.FirstName as SellerName, Seller.LastName as SellerLast, Buyer.FirstName as BuyerName, Buyer.LastName as BuyerLast, S.ShiftName, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate FROM ShiftTransaction ST JOIN User Seller ON ST.SellerID = Seller.UserID JOIN User Buyer ON ST.BuyerID = Buyer.UserID JOIN NurseSchedule NS ON ST.ScheduleID = NS.ScheduleID JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE ST.Status = 'Pending_HeadNurse' ORDER BY ST.CreatedAt ASC`;
        const [results] = await dbPool.query(sql);
        res.json({ success: true, results });
    } catch (err) { console.error("Fetch Pending Market Error:", err); res.status(500).json({ success: false, message: "DB Error" }); }
});
// ✅ API อนุมัติการซื้อขาย (Full Updated Version)
app.post('/api/admin/market/action', authenticateToken, async (req, res) => {
    const { transactionId, action, adminId } = req.body;
    const connection = await dbPool.getConnection();
    try {
        await connection.beginTransaction();

        // ดึงข้อมูลวันที่และชื่อกะเพื่อใช้ในการแจ้งเตือน (ป้องกัน Invalid Date)
        const [trans] = await connection.query(`
            SELECT ST.*, DATE_FORMAT(NS.Nurse_Date, '%Y-%m-%d') as ShiftDate, S.ShiftName 
            FROM ShiftTransaction ST 
            JOIN NurseSchedule NS ON ST.ScheduleID = NS.ScheduleID 
            JOIN Shift S ON NS.Shift_id = S.Shift_id
            WHERE ST.TransactionID = ? FOR UPDATE`, [transactionId]);
        
        if (trans.length === 0) throw new Error("ไม่พบรายการ");
        const trade = trans[0];

        const createNoti = `INSERT INTO Notifications (UserID, Title, Message, Type, RelatedDate, RelatedShift, CreatedAt) 
                            VALUES (?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 HOUR))`;

        if (action === 'reject') {
            // อัปเดตสถานะเป็น Rejected (ตัวใหญ่ตามรูป DB)
            await connection.query("UPDATE ShiftTransaction SET Status = 'Rejected', ApprovedBy = ? WHERE TransactionID = ?", [adminId, transactionId]);
            await connection.query(createNoti, [trade.BuyerID, 'การซื้อเวรถูกปฏิเสธ', 'หัวหน้าปฏิเสธคำขอซื้อเวรของคุณ', 'system', trade.ShiftDate, trade.ShiftName]);
            
        } else if (action === 'approve') {
            // 1. อัปเดตสถานะเป็น Completed และเปลี่ยนเจ้าของเวรใน NurseSchedule
            await connection.query("UPDATE ShiftTransaction SET Status = 'Completed', ApprovedBy = ? WHERE TransactionID = ?", [adminId, transactionId]);
            await connection.query("UPDATE PostSell SET Status = 'Sold' WHERE PostSellID = ?", [trade.PostSellID]);
            await connection.query("UPDATE NurseSchedule SET UserID = ? WHERE ScheduleID = ?", [trade.BuyerID, trade.ScheduleID]);
            
            // 2. จัดการสถิติ (ป้องกัน Error 1364 ด้วย Default Values ใน DB)
            const statsSql = `INSERT INTO NurseStatistics (UserID, Year, Month, ShiftsSold, TotalShifts, CreatedAt) 
                              VALUES (?, YEAR(NOW()), MONTH(NOW()), 1, 1, DATE_ADD(NOW(), INTERVAL 7 HOUR)) 
                              ON DUPLICATE KEY UPDATE ShiftsSold = ShiftsSold + 1, TotalShifts = TotalShifts + 1`;
            
            await connection.query(statsSql, [trade.SellerID]);
            await connection.query(statsSql.replace('ShiftsSold', 'ShiftsBought'), [trade.BuyerID]);

            // 3. ส่งแจ้งเตือนแบบอ่านอย่างเดียว (แก้ปัญหา Invalid Date)
            await connection.query(createNoti, [trade.BuyerID, 'การซื้อเวรสำเร็จ', `อนุมัติการซื้อเวรวันที่ ${trade.ShiftDate} แล้ว`, 'system', trade.ShiftDate, trade.ShiftName]);
            await connection.query(createNoti, [trade.SellerID, 'การขายเวรสำเร็จ', `อนุมัติการขายเวรวันที่ ${trade.ShiftDate} แล้ว`, 'system', trade.ShiftDate, trade.ShiftName]);
        }

        await connection.commit();
        res.json({ success: true, message: "ดำเนินการเรียบร้อย" });
    } catch (err) { 
        await connection.rollback(); 
        res.status(500).json({ success: false, message: err.message }); 
    } finally { connection.release(); }
});
app.post('/api/admin/add-user', authenticateToken, async (req, res) => {
    try {
        // 1. เช็คสิทธิ์ว่าเป็น Admin (RoleID = 1) เท่านั้น
        if (req.user.roleId !== 1) {
            return res.status(403).json({ success: false, message: 'Access Denied: Admins only' });
        }

        const { email, firstName, lastName, roleId } = req.body;

        // 2. ตรวจสอบข้อมูลเบื้องต้น
        if (!email || !firstName) {
            return res.status(400).json({ success: false, message: 'กรุณากรอก Email และชื่อจริง' });
        }

        // 3. สร้างรหัสผ่านสุ่ม + เข้ารหัส
        const rawPassword = generateRandomPassword(8);
        const hashedPassword = await bcrypt.hash(rawPassword, 10);

        // 🔥 LOG รหัสผ่านดูใน Terminal (เผื่อเมลไม่เข้า จะได้เอารหัสตรงนี้ไปเทส)
        console.log(`---------------------------------------------`);
        console.log(`➕ สร้าง User ใหม่: ${email}`);
        console.log(`🔑 รหัสผ่านคือ: ${rawPassword}`);
        console.log(`---------------------------------------------`);

        // 4. บันทึกลง Database
        const sql = `INSERT INTO User (Email, PasswordHash, FirstName, LastName, RoleID, Status, CreatedAt) 
                     VALUES (?, ?, ?, ?, ?, 'active', DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        
        await dbPool.query(sql, [email, hashedPassword, firstName, lastName || '', roleId || 2]);

        // 5. ส่งอีเมลแจ้งเจ้าตัว
        const mailOptions = {
            from: `"AUTONURSESHIFT" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'ยินดีต้อนรับเข้าสู่ระบบ - แจ้งรหัสผ่าน',
            html: `
                <div style="padding: 20px; border: 1px solid #ddd; border-radius: 10px; font-family: sans-serif;">
                    <h2 style="color: #2c3e50;">ยินดีต้อนรับคุณ ${firstName}</h2>
                    <p>ผู้ดูแลระบบได้สร้างบัญชีผู้ใช้งานให้คุณแล้ว รายละเอียดดังนี้:</p>
                    <hr>
                    <p><b>Email:</b> ${email}</p>
                    <p><b>Password:</b> <span style="background-color: #f1f1f1; padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 16px;">${rawPassword}</span></p>
                    <hr>
                    <p style="color: #7f8c8d; font-size: 12px;">กรุณาเปลี่ยนรหัสผ่านหลังเข้าสู่ระบบครั้งแรก</p>
                </div>
            `
        };

        // สั่งส่งเมล (ไม่ต้องรอให้เสร็จ เพื่อความเร็ว)
        transporter.sendMail(mailOptions).catch(err => console.error("Email Error:", err));

        res.json({ success: true, message: 'เพิ่มผู้ใช้งานเรียบร้อยแล้ว' });

    } catch (err) {
        console.error("Add User Error:", err);
        // เช็คว่าอีเมลซ้ำไหม
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ success: false, message: 'อีเมลนี้มีอยู่ในระบบแล้ว' });
        }
        res.status(500).json({ success: false, message: 'Server Error: ' + err.message });
    }
});
app.get('/api/admin/check-submission-status', authenticateToken, async (req, res) => {
    try {
        // ดึงสถานะปัจจุบันจากตาราง SystemSettings
        const [rows] = await dbPool.query("SELECT SettingValue FROM SystemSettings WHERE SettingKey = 'WindowStatus'");
        const isOpen = rows.length > 0 && rows[0].SettingValue === 'Open';
        res.json({ success: true, isOpen: isOpen });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
// ==========================================
// 8. SERVER EXPORT (สำคัญสำหรับ Vercel)
// ถ้า Run บนเครื่องตัวเอง (Local) ให้ start port
if (require.main === module) {
    app.listen(port, () => {
        console.log(`🚀 Server running locally at http://localhost:${port}/`);
    });
}

// ส่งออก app เพื่อให้ Vercel นำไปทำเป็น Serverless Function
module.exports = app;
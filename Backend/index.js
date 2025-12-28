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
const port = process.env.PORT || 3000; 
// Library สำหรับ Vercel/Cloudinary ---
const cloudinary = require('cloudinary').v2;
const moment = require('moment');
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
        folder: 'autonurseshift-profiles',
        allowed_formats: ['jpg', 'png', 'jpeg'],
        transformation: [
            { width: 400, height: 400, crop: 'fill', gravity: 'face' }, 
            { quality: 'auto', fetch_format: 'auto' }
        ]
    },
});
const upload = multer({ storage: storage });
function getPublicIdFromUrl(url) {
    const parts = url.split('/');
    const fileName = parts[parts.length - 1]; 
    const publicId = fileName.split('.')[0]; 
    return `autonurseshift-profiles/${publicId}`;
}

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
async function checkFatigueStatus(dbPool, userId, targetDate, targetShiftId, options = {}) {
    try {
        const { ignoreWeeklyLimit = false } = options;
        // 1. ตรวจสอบเวรใน "วันเดียวกัน" (Daily Checks)
        const [existing] = await dbPool.query(
            "SELECT NS.Shift_id, S.ShiftName FROM NurseSchedule NS JOIN Shift S ON NS.Shift_id = S.Shift_id WHERE NS.UserID = ? AND NS.Nurse_Date = ?", 
            [userId, targetDate]
        );
        // วนลูปเช็คเวรเดิมที่มีอยู่ในวันนี้
        for (const row of existing) {
            const existingShiftId = row.Shift_id;
            // กฎ: ห้ามลงเวรซ้ำกะเดิม (เช่น มีเช้าแล้ว จะรับเช้าอีกไม่ได้)
            if (existingShiftId == targetShiftId) {
                return { safe: false, message: `คุณมีเวร ${row.ShiftName} ในวันนี้อยู่แล้ว` };
            }
            // กฎ: ห้ามควบ "บ่าย(2) + ดึก(3)" (อันตรายเกินไป ร่างกายไม่ได้พัก)
            // เช็คทั้งขาไปและขากลับ
            if ((targetShiftId == 2 && existingShiftId == 3) || (targetShiftId == 3 && existingShiftId == 2)) {
                return { safe: false, message: "อันตราย: ห้ามควงเวร บ่าย-ต่อ-ดึก" };
            }
            
            // ✅ หมายเหตุ: ไม่มีโค้ดห้าม เช้า(1)+บ่าย(2) แล้ว -> แปลว่าทำได้
        }
        // กฎ: ห้ามเกิน 2 เวรใน 1 วัน (ป้องกันการควง 3 กะ เช้า-บ่าย-ดึก)
        if (existing.length >= 2) {
             return { safe: false, message: "คุณมี 2 เวรในวันนี้แล้ว ไม่สามารถรับเพิ่มได้" };
        }
        // 2. ตรวจสอบกฎ "ข้ามวัน" (ดึกเมื่อวาน -> ห้ามเช้าวันนี้)
        if (targetShiftId == 1) { // 1 = เวรเช้า
            const [prevNight] = await dbPool.query(
                "SELECT * FROM NurseSchedule WHERE UserID = ? AND Nurse_Date = DATE_SUB(?, INTERVAL 1 DAY) AND Shift_id = 3", 
                [userId, targetDate] // 3 = เวรดึก
            );
            if (prevNight.length > 0) {
                return { safe: false, message: "ผิดกฎความปลอดภัย: ห้ามเข้าเวรเช้าต่อจากเวรดึกของเมื่อวาน (ต้องพักอย่างน้อย 12 ชม.)" };
            }
        }
        // 3. ตรวจสอบโควตา "รายสัปดาห์" (Max 7 Shifts / Week)
        // ถ้า ignoreWeeklyLimit เป็น true (เช่น ตอนซื้อขายเวร) เราจะข้ามบล็อกนี้ไปเลย
        if (!ignoreWeeklyLimit) { 
            const startOfWeek = moment(targetDate).startOf('isoWeek').format('YYYY-MM-DD');
            const endOfWeek = moment(targetDate).endOf('isoWeek').format('YYYY-MM-DD');

            // นับจำนวนเวรที่มีอยู่แล้วในสัปดาห์นั้น
            const [countRes] = await dbPool.query(
                `SELECT COUNT(*) as total_shifts 
                 FROM NurseSchedule 
                 WHERE UserID = ? AND Nurse_Date BETWEEN ? AND ?`,
                [userId, startOfWeek, endOfWeek]
            );

            const currentShifts = countRes[0].total_shifts || 0;
            
            // ถ้าตอนนี้มี 7 เวรแล้ว รับเพิ่มอีก 1 จะเป็น 8 -> ห้าม
            if (currentShifts >= 7) {
                return { 
                    safe: false, 
                    message: `คุณทำงานครบ 7 เวร (56 ชม.) ในสัปดาห์นี้แล้ว` 
                };
            }
        }

        // ผ่านทุกด่าน
        return { safe: true };

    } catch (err) {
        console.error("Fatigue Check Error:", err);
        return { safe: false, message: "เกิดข้อผิดพลาดในการตรวจสอบความปลอดภัย" };
    }
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
// 5. API ROUTES
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
// Logout
app.post('/logout', async (req, res) => {
    const userId = req.body.userId;
    console.log("--> Logout Request Received:", userId);

    try {
        res.clearCookie('token'); 
        res.json({ message: "Logged out successfully" });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

//  API Update Profile Image (ใช้ Cloudinary URL)
app.post('/api/update-profile-image', authenticateToken, upload.single('profileImage'), async (req, res) => {
    const userId = req.body.userId;
    if (!userId || !req.file) return res.status(400).json({ success: false, message: "Missing data" });

    try {
        // 1. ดึงข้อมูลรูปภาพเดิมจากฐานข้อมูลก่อน
        const [user] = await dbPool.query("SELECT ProfileImage FROM User WHERE UserID = ?", [userId]);
        const oldImageUrl = user[0]?.ProfileImage;

        // 2. ถ้ามีรูปเดิม และเป็นรูปจาก Cloudinary ให้สั่งลบ
        if (oldImageUrl && oldImageUrl.includes('cloudinary')) {
            const publicId = getPublicIdFromUrl(oldImageUrl);
            if (publicId) {
                // สั่งลบไฟล์ใน Cloudinary (ใช้ uploader.destroy)
                await cloudinary.uploader.destroy(publicId);
                console.log("Deleted old image from Cloudinary:", publicId);
            }
        }

        // 3. บันทึก URL รูปใหม่ที่ Cloudinary เพิ่งสร้างให้ (req.file.path)
        const newImagePath = req.file.path; 
        await dbPool.query("UPDATE User SET ProfileImage = ? WHERE UserID = ?", [newImagePath, userId]);

        res.json({ 
            success: true, 
            message: "อัปเดตรูปโปรไฟล์สำเร็จและลบรูปเก่าเรียบร้อย", 
            imagePath: newImagePath 
        });

    } catch (err) {
        console.error("Update Image Error:", err);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการอัปโหลด" });
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

        // --- เริ่มต้นส่วนแก้ไข HTML Template ---
        const mailOptions = {
            from: `"AUTONURSESHIFT Support" <${process.env.EMAIL_USER}>`, // เพิ่มคำว่า Support ให้ดูโปรขึ้น
            to: Email,
            subject: '🔑 รหัส OTP สำหรับรีเซ็ตรหัสผ่านของคุณ',
            html: `
              <!DOCTYPE html>
              <html>
              <head>
                <style>
                  body { font-family: 'Sarabun', Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 0; }
                  .container { max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.05); overflow: hidden; border: 1px solid #e1e4e8; }
                  .header { background-color: #007bff; padding: 25px; text-align: center; }
                  .header h1 { color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px; }
                  .content { padding: 30px; text-align: center; color: #333333; }
                  .otp-box { background-color: #f8f9fa; border: 2px dashed #007bff; border-radius: 8px; padding: 15px 25px; margin: 25px 0; font-size: 36px; font-weight: bold; letter-spacing: 5px; color: #007bff; display: inline-block; }
                  .footer { background-color: #f4f7f6; padding: 15px; text-align: center; font-size: 12px; color: #888888; border-top: 1px solid #eeeeee; }
                  .warning { color: #dc3545; font-size: 14px; margin-top: 15px; }
                  p { line-height: 1.6; margin-bottom: 10px; }
                </style>
              </head>
              <body>
                <div class="container">
                  <div class="header">
                    <h1>AUTONURSESHIFT</h1>
                  </div>
                  <div class="content">
                    <h2 style="color: #444; margin-top: 0;">รหัสยืนยันตัวตน (OTP)</h2>
                    <p style="font-size: 16px; color: #555;">เรียน ผู้ใช้งาน,</p>
                    <p>ระบบได้รับคำขอให้รีเซ็ตรหัสผ่านสำหรับบัญชีของคุณ<br>โปรดใช้รหัส OTP ด้านล่างนี้เพื่อดำเนินการต่อ:</p>
                    
                    <div class="otp-box">
                      ${otp}
                    </div>
                    
                    <p class="warning">⚠️ รหัสนี้จะหมดอายุภายใน 10 นาที</p>
                    <p style="font-size: 13px; color: #777; margin-top: 30px;">
                      หากคุณไม่ได้เป็นผู้ส่งคำขอนี้ โปรดอย่าส่งรหัสนี้ให้ผู้อื่น<br>บัญชีของคุณยังคงปลอดภัย
                    </p>
                  </div>
                  <div class="footer">
                    <p>&copy; ${new Date().getFullYear()} AUTONURSESHIFT System. All rights reserved.</p>
                  </div>
                </div>
              </body>
              </html>
            `
        };
        await transporter.sendMail(mailOptions);
        res.status(200).send({ message: 'ส่ง OTP แล้ว' });

    } catch (err) { console.error(err); res.status(500).send({ message: err.message }); }
});

// Verify OTP
app.post("/verify-otp", async (req, res) => {
    // รับค่าจากหน้าบ้าน (Frontend ส่งมาเป็น key: email, otp)
    const { email, otp } = req.body;

    try {
        // 1. หา UserID จากอีเมล
        const [users] = await dbPool.query("SELECT UserID FROM User WHERE Email = ?", [email]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: "ไม่พบอีเมลผู้ใช้งานในระบบ" });
        }

        const userId = users[0].UserID;

        // 2. ดึง OTP ล่าสุดที่ยังไม่หมดอายุของ User คนนี้
        const [otps] = await dbPool.query(
            "SELECT * FROM Password_reset_otp WHERE UserID = ? ORDER BY otp_id DESC LIMIT 1", 
            [userId]
        );

        if (otps.length === 0) {
            return res.status(400).json({ success: false, message: "ไม่พบข้อมูลการขอ OTP กรุณากดขอรหัสใหม่" });
        }

        const otpData = otps[0];

        // --- [จุดที่แก้ไข] ---
        // แปลงเป็น String ทั้งคู่ก่อนเทียบ เพื่อแก้ปัญหาหน้าบ้านส่ง "368329" (String) แต่ DB เก็บ 368329 (Int)
        // และเช็คว่าถูกใช้งานไปแล้วหรือยัง
        if (String(otpData.otp_code) !== String(otp)) {
            return res.status(400).json({ success: false, message: "รหัส OTP ไม่ถูกต้อง" });
        }

        if (otpData.is_used === 1) {
             return res.status(400).json({ success: false, message: "รหัส OTP นี้ถูกใช้งานไปแล้ว" });
        }
        
        // 3. เช็ควันหมดอายุ
        // (สมมติว่า function getThaiTimeInMySQLFormat ทำงานถูกต้องอยู่แล้ว)
        // เปรียบเทียบเวลาปัจจุบัน กับ เวลาหมดอายุใน DB
        const currentTime = getThaiTimeInMySQLFormat(0); 
        const expireTime = new Date(otpData.expires_at).toLocaleString('sv-SE'); // จัด Format ให้ตรงกันเพื่อเทียบ string

        if (currentTime > expireTime) {
            return res.status(400).json({ success: false, message: "รหัส OTP หมดอายุแล้ว" });
        }

        // ถ้าผ่านทุกด่าน
        res.json({ success: true, message: "OTP ถูกต้อง ยืนยันตัวตนสำเร็จ" });

    } catch (err) { 
        console.error("Verify OTP Error:", err);
        res.status(500).json({ success: false, message: "Server Error: ไม่สามารถตรวจสอบข้อมูลได้" }); 
    }
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
                
                await dbPool.query(sql, [email, hashedPassword, firstName, lastName, roleId]);

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
// ✅ แก้ไข API นับจำนวน Badge สำหรับพยาบาล (Role 2) และรวมการแจ้งเตือนระบบ
app.get('/api/notifications/unread-count/:userId', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        const userRole = req.user.roleId; 

        // 1. นับแจ้งเตือนจากระบบ (Notifications Table) ที่ยังไม่อ่าน
        const [systemNotis] = await dbPool.query(
            "SELECT COUNT(*) as count FROM Notifications WHERE UserID = ? AND IsRead = 0",
            [userId]
        );

        let pendingActionCount = 0;

        // 2. ถ้าเป็นพยาบาล (Role 2) ให้ไปนับงานที่เพื่อนส่งมาขอแลก/ซื้อด้วย
        if (userRole === 2) {
            // นับคำขอแลกเวรที่ส่งมาถึงเรา และยังรอเราตอบ (status = 'pending')
            const [swapReqs] = await dbPool.query(
                "SELECT COUNT(*) as count FROM Shift_Exchange WHERE responder_id = ? AND status = 'pending'",
                [userId]
            );
            // นับคำขอซื้อเวรที่ส่งมาถึงเรา (Status = 'Pending_Seller')
            const [buyReqs] = await dbPool.query(
                "SELECT COUNT(*) as count FROM ShiftTransaction WHERE SellerID = ? AND Status = 'Pending_Seller'",
                [userId]
            );
            
            pendingActionCount = (swapReqs[0].count || 0) + (buyReqs[0].count || 0);
        }

        // รวมยอดทั้งหมดส่งกลับไปที่ Badge
        res.json({ 
            success: true, 
            count: (systemNotis[0].count || 0) + pendingActionCount 
        });

    } catch (err) { 
        console.error("Unread Count API Error:", err);
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});
// ✅ Correct Route for /api/admin/pending-counts
app.get('/api/admin/pending-counts', authenticateToken, async (req, res) => {
    // Debugging line
    console.log("User Role in Request:", req.user.roleId);

    // Loose equality (==) handles if roleId is string '1' or number 1
    if (req.user.roleId != 1) {
        return res.status(403).json({ success: false, message: 'Access Denied: Head Nurse Only' });
    }

    try {
        const [swap] = await dbPool.query("SELECT COUNT(*) as count FROM Shift_Exchange WHERE status = 'accepted'");
        const [trade] = await dbPool.query("SELECT COUNT(*) as count FROM ShiftTransaction WHERE Status = 'Pending_HeadNurse'");

        res.json({ 
            success: true, 
            total: (swap[0].count || 0) + (trade[0].count || 0), 
            swapCount: swap[0].count || 0, 
            tradeCount: trade[0].count || 0 
        });
    } catch (err) { 
        console.error("Pending Counts Error:", err);
        res.status(500).json({ success: false }); 
    }
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

app.post('/api/set-constraints', authenticateToken, async (req, res) => {
    const { userId, settingPeriod, daysOffMinimum, fixedDaysOff, preferences } = req.body;
    
    try {
        // 1. แปลง Array วันหยุด เป็น String
        const fixedDaysString = Array.isArray(fixedDaysOff) ? JSON.stringify(fixedDaysOff) : fixedDaysOff;

        // 2. SQL: เพิ่มคอลัมน์ Reason เข้าไปในคำสั่ง INSERT
        const sql = `
            INSERT INTO Constraints (
                UserID, SettingPeriod, Constraint_Date, DaysOffMin, FixedDaysOff, 
                PrefMorning, PrefAfternoon, PrefNight, Reason, CreatedAt
            ) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 HOUR))
            ON DUPLICATE KEY UPDATE 
                Constraint_Date = VALUES(Constraint_Date),
                DaysOffMin = VALUES(DaysOffMin), 
                FixedDaysOff = VALUES(FixedDaysOff),
                PrefMorning = VALUES(PrefMorning),
                PrefAfternoon = VALUES(PrefAfternoon),
                PrefNight = VALUES(PrefNight),
                Reason = VALUES(Reason)
        `;

        // 3. ส่งค่า 'User Preference' ไปใส่ในช่อง Reason เพื่อกัน Error
        await dbPool.query(sql, [
            userId, 
            settingPeriod, 
            settingPeriod, 
            daysOffMinimum, 
            fixedDaysString, 
            preferences.Morning, 
            preferences.Afternoon, 
            preferences.Night,
            'User Preference' // 👈 ค่าสำหรับช่อง Reason (ใส่ไว้กัน Error)
        ]);

        res.json({ success: true, message: "บันทึกข้อจำกัดลงตาราง Constraints เรียบร้อยแล้ว" });

    } catch (err) {
        console.error("Database Save Error:", err);
        res.status(500).json({ success: false, message: "Server Error: " + err.message });
    }
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
        const { requesterId, requesterScheduleId, postId, targetScheduleId, reason } = req.body;

        // 1. เช็คข้อมูลพื้นฐาน
        if (!requesterId || !requesterScheduleId) {
            return res.status(400).json({ success: false, message: 'ข้อมูลฝั่งคนขอไม่ครบถ้วน' });
        }

        let responderId = null;
        let responderScheduleId = null;

        // 2. หาข้อมูลเวรปลายทาง (Responder)
        if (postId) {
            const [postData] = await dbPool.query("SELECT UserID, ScheduleID FROM ExchangePost WHERE ExchangePostID = ?", [postId]);
            if (postData.length === 0) return res.status(404).json({ success: false, message: 'ไม่พบประกาศนี้' });
            responderId = postData[0].UserID;
            responderScheduleId = postData[0].ScheduleID;
        } else if (targetScheduleId) {
            const [scheduleData] = await dbPool.query("SELECT UserID, ScheduleID FROM NurseSchedule WHERE ScheduleID = ?", [targetScheduleId]);
            if (scheduleData.length === 0) return res.status(404).json({ success: false, message: 'ไม่พบเวรที่ต้องการแลก' });
            responderId = scheduleData[0].UserID;
            responderScheduleId = scheduleData[0].ScheduleID;
        } else {
            return res.status(400).json({ success: false, message: 'ระบุข้อมูลไม่ครบ (ต้องมี postId หรือ targetScheduleId)' });
        }

        if (responderId == requesterId) return res.status(400).json({ success: false, message: 'คุณจะแลกเวรกับตัวเองไม่ได้' });

        // ==================================================================================
        // 🛡️ SECURITY CHECK: ตรวจสอบกฎความปลอดภัย (Fatigue Rules) ก่อนอนุญาตให้ส่งคำขอ
        // ==================================================================================
        
        // A. ดึงรายละเอียดเวรของทั้ง 2 ฝั่ง (วันที่ และ กะ)
        const [reqShiftInfo] = await dbPool.query(
            "SELECT Nurse_Date, Shift_id FROM NurseSchedule WHERE ScheduleID = ?", 
            [requesterScheduleId]
        );
        const [resShiftInfo] = await dbPool.query(
            "SELECT Nurse_Date, Shift_id FROM NurseSchedule WHERE ScheduleID = ?", 
            [responderScheduleId]
        );

        if (reqShiftInfo.length === 0 || resShiftInfo.length === 0) {
            return res.status(404).json({ success: false, message: "ไม่พบข้อมูลรายละเอียดเวร" });
        }

        const requesterShift = reqShiftInfo[0]; // เวรเดิมของคนขอ (กำลังจะโยนออก)
        const responderShift = resShiftInfo[0]; // เวรใหม่ที่คนขอจะได้ (กำลังจะรับเข้า)

        // B. เช็คความปลอดภัยของ "คนขอ" (Requester) ที่จะไปรับเวรใหม่
        // "คนขอ" กำลังจะไปทำเวรในวันที่ของ Responder -> เช็คว่าปลอดภัยไหม?
        const safetyRequester = await checkFatigueStatus(dbPool, requesterId, responderShift.Nurse_Date, responderShift.Shift_id);
        if (!safetyRequester.safe) {
            return res.status(400).json({ 
                success: false, 
                message: `คุณไม่สามารถแลกเวรนี้ได้ (ผิดกฎความปลอดภัย): ${safetyRequester.message}` 
            });
        }

        // C. เช็คความปลอดภัยของ "คนถูกขอ" (Responder) ที่จะต้องมารับเวรเรา
        // "คนถูกขอ" ต้องมารับเวรในวันที่ของเรา -> เช็คว่าเขาไหวไหม?
        const safetyResponder = await checkFatigueStatus(dbPool, responderId, requesterShift.Nurse_Date, requesterShift.Shift_id);
        if (!safetyResponder.safe) {
            return res.status(400).json({ 
                success: false, 
                message: `ไม่สามารถส่งคำขอได้ เนื่องจากเพื่อนจะผิดกฎความปลอดภัย: ${safetyResponder.message}` 
            });
        }

        // ==================================================================================
        // สิ้นสุดการตรวจสอบ
        // ==================================================================================

        // 4. เช็คว่าเคยขอซ้ำไหม
        const [existing] = await dbPool.query(
            "SELECT exchange_id FROM Shift_Exchange WHERE requester_schedule_id = ? AND responder_schedule_id = ? AND status = 'pending'", 
            [requesterScheduleId, responderScheduleId]
        );
        if (existing.length > 0) return res.status(400).json({ success: false, message: 'คำขอนี้รอการอนุมัติอยู่แล้ว' });

        // 5. บันทึก
        const sql = `INSERT INTO Shift_Exchange (requester_id, requester_schedule_id, responder_id, responder_schedule_id, status, reason, created_at) VALUES (?, ?, ?, ?, 'pending', ?, DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        await dbPool.query(sql, [requesterId, requesterScheduleId, responderId, responderScheduleId, reason]);

        res.json({ success: true, message: 'ส่งคำขอเรียบร้อย (ผ่านการตรวจสอบความปลอดภัยแล้ว)' });

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
        // 1. ดึงข้อมูลประกาศขาย และข้อมูลเวร (วันที่/กะ) มาเพื่อเช็คความปลอดภัย
        const [posts] = await dbPool.query(`
            SELECT ps.UserID, ps.ScheduleID, ps.Price, ns.Nurse_Date, ns.Shift_id 
            FROM PostSell ps
            JOIN NurseSchedule ns ON ps.ScheduleID = ns.ScheduleID
            WHERE ps.PostSellID = ?`, 
            [sellId]
        );
        if (posts.length === 0) return res.status(404).json({ success: false, message: "ไม่พบประกาศ" });
        const post = posts[0];
        if (post.UserID == userId) return res.status(400).json({ success: false, message: "ไม่สามารถขอซื้อเวรตัวเองได้" });
        // === ส่วนที่เพิ่ม: ตรวจสอบความปลอดภัย (Fatigue Check) ===
        const fatigue = await checkFatigueStatus(dbPool, userId, post.Nurse_Date, post.Shift_id);
        if (!fatigue.safe) {
            return res.status(400).json({ success: false, message: fatigue.message });
        }
        // ===================================================
        // 2. ถ้าผ่านการเช็ค ให้ทำการบันทึกคำขอซื้อเวร
        const sql = `INSERT INTO ShiftTransaction (PostSellID, SellerID, BuyerID, ScheduleID, Price, Status, CreatedAt) 
                     VALUES (?, ?, ?, ?, ?, 'Pending_Seller', DATE_ADD(NOW(), INTERVAL 7 HOUR))`;
        await dbPool.query(sql, [sellId, post.UserID, userId, post.ScheduleID, post.Price]);
        res.json({ success: true, message: 'ส่งคำขอสำเร็จ รอเจ้าของเวรตอบรับ' });
    } catch (err) { 
        console.error("Trade Request Error:", err); 
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
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
// =========================================================================
// API: ระบบจัดเวรอัตโนมัติ (Full Intelligent Engine)
// - กฎ 1: เมื่อวานดึก -> ห้ามวันนี้เช้า (Fatigue)
// - กฎ 2: ห้ามควบ บ่าย+ดึก หรือ เกิน 2 เวร/วัน (Daily Limit)
// - กฎ 3: ⭐️ ห้ามลงเวรดึกเกิน 2 ครั้ง/สัปดาห์ (Weekly Night Limit) ⭐️
// - กฎ 4: เกลี่ยเวรดึกให้เท่าเทียม (Fairness Weighting)
// - กฎ 5: ใช้คะแนนความพึงพอใจ 1-5 เป็นน้ำหนักในการสุ่ม (Preference Weight)
// =========================================================================
app.post('/api/admin/generate-schedule', authenticateToken, async (req, res) => {
    // 1. ตรวจสอบสิทธิ์ (Admin Only)
    if (req.user.roleId !== 1) {
        return res.status(403).json({ success: false, message: "สิทธิ์ไม่ถูกต้อง: เฉพาะหัวหน้าพยาบาลเท่านั้น" });
    }

    const connection = await dbPool.getConnection();
    try {
        await connection.beginTransaction();

        // 2. ดึงการตั้งค่าโควตาจาก SystemSettings
        const [settings] = await connection.query("SELECT * FROM SystemSettings");
        const getQuota = (key) => parseInt(settings.find(s => s.SettingKey === key)?.SettingValue || 0);
        
        const quotas = {
            1: getQuota('QuotaMorning'),   // 1 = เช้า
            2: getQuota('QuotaAfternoon'), // 2 = บ่าย
            3: getQuota('QuotaNight')      // 3 = ดึก
        };

        // 3. เตรียมข้อมูลพยาบาลและข้อจำกัด (Constraints)
        // ✅ [แก้ไข] : ดึงทั้ง RoleID 1 (หัวหน้า) และ 2 (พยาบาล)
        const [nurses] = await connection.query("SELECT UserID FROM User WHERE RoleID IN (1, 2) AND Status = 'active'");
        
        const [allConstraints] = await connection.query("SELECT * FROM Constraints");

        // 4. กำหนดช่วงเวลา (เดือนถัดไป)
        const targetMonth = moment().add(1, 'month');
        const daysInMonth = targetMonth.daysInMonth();
        const yearMonth = targetMonth.format('YYYY-MM');

        // ล้างเวรเก่าของเดือนนั้นทิ้งก่อน (Re-generate)
        await connection.query("DELETE FROM NurseSchedule WHERE Nurse_Date LIKE ?", [`${yearMonth}%`]);

        // 5. เตรียมข้อมูล "เวรดึกวันสุดท้ายของเดือนที่แล้ว" (เพื่อเช็คความต่อเนื่องวันที่ 1)
        const lastMonthEnd = moment().endOf('month').format('YYYY-MM-DD');
        const [prevMonthNightShifts] = await connection.query(
            "SELECT UserID FROM NurseSchedule WHERE Nurse_Date = ? AND Shift_id = 3", 
            [lastMonthEnd]
        );
        let blockedFromYesterdayNight = prevMonthNightShifts.map(row => row.UserID);

        // 🟢 ตัวแปรติดตามยอดเวรดึกสะสมรายเดือน (เพื่อ Fairness: ใครทำน้อยให้โดนเยอะ)
        const monthlyNightShiftCount = {}; 
        nurses.forEach(n => monthlyNightShiftCount[n.UserID] = 0);

        // 🔵 ตัวแปรติดตามยอดเวรดึกรายสัปดาห์ (กฎ: ห้ามเกิน 2 ครั้ง/สัปดาห์)
        const weeklyNightShiftTracker = {};

        // เก็บรายการวันที่คนไม่พอ (Report)
        const incompleteShifts = [];

        // ==========================================
        // 🚀 เริ่มวนลูปจัดเวรรายวัน (Day 1 -> Day 30/31)
        // ==========================================
        for (let d = 1; d <= daysInMonth; d++) {
            const currentDateStr = `${yearMonth}-${String(d).padStart(2, '0')}`;
            const currentWeekNum = moment(currentDateStr).isoWeek(); // เลขสัปดาห์ของปี
            const dailyAssignments = {}; // เก็บว่าวันนี้ใครได้เวรบ้าง

            // ลำดับการจัด: ดึก(3) -> บ่าย(2) -> เช้า(1)
            const shiftOrder = [3, 2, 1];

            for (const shiftId of shiftOrder) {
                const quotaNeeded = quotas[shiftId];
                let assignedCount = 0;

                // 1. คัดกรองคนที่มีสิทธิ์ลง (Candidate Pool)
                const candidates = nurses.filter(nurse => {
                    const uid = nurse.UserID;
                    const myShiftsToday = dailyAssignments[uid] || [];

                    // --- กฎความปลอดภัย (Safety & Fatigue) ---
                    if (shiftId === 1 && blockedFromYesterdayNight.includes(uid)) return false; // เมื่อวานดึก วันนี้ห้ามเช้า
                    if (myShiftsToday.length >= 2) return false; // ห้ามเกิน 2 เวร/วัน
                    if (myShiftsToday.includes(shiftId)) return false; // ห้ามซ้ำกะเดิม
                    if (shiftId === 3 && myShiftsToday.includes(2)) return false; // มีบ่าย ห้ามลงดึก
                    if (shiftId === 2 && myShiftsToday.includes(3)) return false; // มีดึก ห้ามลงบ่าย

                    // --- ⭐️ กฎใหม่: ห้ามเวรดึกเกิน 2 ครั้ง/สัปดาห์ ---
                    if (shiftId === 3) {
                        const myWeeklyRecord = weeklyNightShiftTracker[uid] || {};
                        const currentWeekCount = myWeeklyRecord[currentWeekNum] || 0;
                        if (currentWeekCount >= 2) return false; // ตัดสิทธิ์ถ้าครบ 2 แล้ว
                    }

                    // --- กฎวันหยุด (Fixed Day Off) ---
                    const con = allConstraints.find(c => c.UserID === uid && moment(c.SettingPeriod).format('YYYY-MM') === yearMonth);
                    if (con && con.FixedDaysOff) {
                        try {
                            // รองรับทั้ง Array และ String JSON
                            const fixedOff = typeof con.FixedDaysOff === 'string' ? JSON.parse(con.FixedDaysOff) : con.FixedDaysOff;
                            if (fixedOff.includes(currentDateStr)) return false;
                        } catch (e) {}
                    }
                    
                    // --- คำนวณคะแนนพื้นฐาน (Preference 1-5) ---
                    let baseScore = 3;
                    if (con) {
                        if (shiftId === 1) baseScore = con.PrefMorning || 3;
                        if (shiftId === 2) baseScore = con.PrefAfternoon || 3;
                        if (shiftId === 3) baseScore = con.PrefNight || 3;
                    }
                    nurse.tempWeight = baseScore;
                    return true;
                });

                // 2. ⚖️ ปรับน้ำหนักสำหรับ "เวรดึก" (Fairness Logic)
                if (shiftId === 3) {
                    candidates.forEach(n => {
                        const fairnessFactor = 10 / (1 + monthlyNightShiftCount[n.UserID]);
                        n.tempWeight = n.tempWeight * fairnessFactor;
                    });
                }

                // 3. สุ่มเลือกคนแบบถ่วงน้ำหนัก (Weighted Random)
                for (let i = 0; i < quotaNeeded; i++) {
                    if (candidates.length === 0) break;

                    const totalWeight = candidates.reduce((sum, n) => sum + n.tempWeight, 0);
                    let randomVal = Math.random() * totalWeight;
                    let selectedIndex = -1;

                    for (let k = 0; k < candidates.length; k++) {
                        if (randomVal < candidates[k].tempWeight) {
                            selectedIndex = k;
                            break;
                        }
                        randomVal -= candidates[k].tempWeight;
                    }
                    if (selectedIndex === -1 && candidates.length > 0) selectedIndex = candidates.length - 1;

                    if (selectedIndex !== -1) {
                        const selectedNurse = candidates[selectedIndex];

                        // บันทึกลง DB
                        await connection.query(
                            "INSERT INTO NurseSchedule (UserID, Nurse_Date, Shift_id) VALUES (?, ?, ?)",
                            [selectedNurse.UserID, currentDateStr, shiftId]
                        );

                        // อัปเดตสถานะรายวัน
                        if (!dailyAssignments[selectedNurse.UserID]) dailyAssignments[selectedNurse.UserID] = [];
                        dailyAssignments[selectedNurse.UserID].push(shiftId);
                        
                        // ถ้าเป็นเวรดึก -> อัปเดตตัวนับต่างๆ
                        if (shiftId === 3) {
                            // 1. ยอดรายเดือน
                            monthlyNightShiftCount[selectedNurse.UserID]++;
                            
                            // 2. ยอดรายสัปดาห์
                            if (!weeklyNightShiftTracker[selectedNurse.UserID]) weeklyNightShiftTracker[selectedNurse.UserID] = {};
                            const currentVal = weeklyNightShiftTracker[selectedNurse.UserID][currentWeekNum] || 0;
                            weeklyNightShiftTracker[selectedNurse.UserID][currentWeekNum] = currentVal + 1;
                        }

                        // เอาคนที่ได้แล้วออกจาก Candidate ของกะนี้
                        candidates.splice(selectedIndex, 1);
                        assignedCount++;
                    }
                }

                // แจ้งเตือนถ้าคนไม่พอ
                if (assignedCount < quotaNeeded) {
                    incompleteShifts.push({
                        date: currentDateStr,
                        shift: (shiftId === 1 ? 'เช้า' : shiftId === 2 ? 'บ่าย' : 'ดึก'),
                        wanted: quotaNeeded,
                        got: assignedCount
                    });
                }

            } // จบ Loop Shift

            // เตรียมข้อมูล Block สำหรับวันพรุ่งนี้
            const [todayNightShifts] = await connection.query(
                "SELECT UserID FROM NurseSchedule WHERE Nurse_Date = ? AND Shift_id = 3",
                [currentDateStr]
            );
            blockedFromYesterdayNight = todayNightShifts.map(row => row.UserID);

        } // จบ Loop Day

        await connection.commit();
        res.json({ 
            success: true, 
            message: incompleteShifts.length > 0 
                ? `จัดเวรเสร็จสิ้น แต่มี ${incompleteShifts.length} กะที่คนไม่พอ` 
                : `จัดตารางเวรเดือน ${targetMonth.format('MMMM YYYY')} สมบูรณ์แบบ!`,
            incompleteShifts: incompleteShifts
        });

    } catch (err) {
        await connection.rollback();
        console.error("Scheduling Error:", err);
        res.status(500).json({ success: false, message: "Error: " + err.message });
    } finally {
        connection.release();
    }
});
// ✅ API ดึงสถานะการส่งข้อจำกัด (สำหรับแสดงบน Dashboard)
app.get('/api/constraint-status', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // 1. คำนวณรอบเดือนถัดไป (ให้ตรงกับตอนบันทึก)
        // เช่น วันนี้ 20 ธ.ค. -> รอบถัดไปคือ 2026-01-01
        const nextMonthStr = moment().add(1, 'month').startOf('month').format('YYYY-MM-DD');

        // 2. นับจำนวนพยาบาลทั้งหมด (Active)
        // (นับ Role 1 และ 2 เพราะหัวหน้าก็ต้องส่ง)
        const [totalRes] = await dbPool.query("SELECT COUNT(*) as count FROM User WHERE RoleID IN (1, 2) AND Status = 'active'");
        const totalNurses = totalRes[0].count;

        // 3. นับจำนวนคนที่ส่งแล้วในรอบนี้
        const [submittedRes] = await dbPool.query("SELECT COUNT(DISTINCT UserID) as count FROM Constraints WHERE SettingPeriod = ?", [nextMonthStr]);
        const submittedCount = submittedRes[0].count;

        // 4. เช็คว่า "ฉัน" ส่งหรือยัง?
        const [myRes] = await dbPool.query("SELECT COUNT(*) as count FROM Constraints WHERE UserID = ? AND SettingPeriod = ?", [userId, nextMonthStr]);
        const iHaveSubmitted = myRes[0].count > 0;

        res.json({
            success: true,
            total: totalNurses,
            submitted: submittedCount,
            myStatus: iHaveSubmitted
        });

    } catch (err) {
        console.error("Constraint Status Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
// ✅ API ดึงข้อจำกัดส่วนตัว (เพื่อนำกลับมาแก้ไข)
app.get('/api/get-my-constraints', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const period = req.query.period; // รับค่าวันที่รอบจัดเวร (เช่น 2026-01-01)

        if (!period) return res.status(400).json({ success: false, message: "Missing Period" });

        const sql = `SELECT * FROM Constraints WHERE UserID = ? AND SettingPeriod = ?`;
        const [rows] = await dbPool.query(sql, [userId, period]);

        if (rows.length > 0) {
            res.json({ success: true, data: rows[0] });
        } else {
            res.json({ success: false, message: "ยังไม่เคยส่งข้อมูล" });
        }

    } catch (err) {
        console.error("Get Constraints Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
// ==========================================
// 9. USER MANAGEMENT (จัดการรายชื่อพยาบาล)
// ==========================================

// API ดึงรายชื่อพยาบาลทั้งหมด (สำหรับหน้า Admin)
app.get('/api/admin/all-users', authenticateToken, async (req, res) => {
    try {
        if (req.user.roleId !== 1) return res.status(403).json({ success: false, message: 'Access Denied' });

        // เรียงลำดับ: Active ขึ้นก่อน, ตามด้วยชื่อ
        const sql = `
            SELECT UserID, FirstName, LastName, Email, RoleID, Status, ProfileImage, CreatedAt 
            FROM User 
            ORDER BY Status ASC, FirstName ASC
        `;
        const [users] = await dbPool.query(sql);
        res.json({ success: true, users });
    } catch (err) {
        console.error("Fetch Users Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// API ปรับสถานะพยาบาล (Active / Inactive)
app.post('/api/admin/update-user-status', authenticateToken, async (req, res) => {
    const { targetUserId, newStatus } = req.body; // newStatus ส่งมาเป็น 'active' หรือ 'inactive'

    try {
        if (req.user.roleId !== 1) return res.status(403).json({ success: false, message: 'Access Denied' });
        
        // ป้องกันการแบนตัวเอง
        if (targetUserId == req.user.userId) {
            return res.status(400).json({ success: false, message: "ไม่สามารถเปลี่ยนสถานะตัวเองได้" });
        }

        await dbPool.query("UPDATE User SET Status = ? WHERE UserID = ?", [newStatus, targetUserId]);

        res.json({ success: true, message: `ปรับสถานะเป็น ${newStatus} เรียบร้อยแล้ว` });
    } catch (err) {
        console.error("Update Status Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
// API สำหรับดึงสถิติรวมของทีมรายเดือน
app.get('/api/admin/team-stats', authenticateToken, async (req, res) => {
    const { month, year } = req.query; 
    
    try {
        // 1. ดึงสถิติรวมทั้งวอร์ดแยกตามกะ
        const [wardStats] = await dbPool.query(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN Shift_id = 1 THEN 1 ELSE 0 END) as morning,
                SUM(CASE WHEN Shift_id = 2 THEN 1 ELSE 0 END) as afternoon,
                SUM(CASE WHEN Shift_id = 3 THEN 1 ELSE 0 END) as night
            FROM NurseSchedule 
            WHERE MONTH(Nurse_Date) = ? AND YEAR(Nurse_Date) = ?
        `, [month, year]);

        // 2. ดึงรายชื่อพยาบาลและสถิติรายบุคคลในเดือนนั้น
        const [nurses] = await dbPool.query(`
            SELECT 
                U.UserID, U.FirstName, U.LastName, U.ProfileImage,
                COUNT(NS.ScheduleID) as total,
                SUM(CASE WHEN NS.Shift_id = 1 THEN 1 ELSE 0 END) as m,
                SUM(CASE WHEN NS.Shift_id = 2 THEN 1 ELSE 0 END) as a,
                SUM(CASE WHEN NS.Shift_id = 3 THEN 1 ELSE 0 END) as n
            FROM User U
            LEFT JOIN NurseSchedule NS ON U.UserID = NS.UserID 
                AND MONTH(NS.Nurse_Date) = ? AND YEAR(NS.Nurse_Date) = ?
            WHERE U.RoleID IN (1, 2) AND U.Status = 'active'
            GROUP BY U.UserID
            ORDER BY total DESC
        `, [month, year]);

        // 3. ดึงรายละเอียดวันทำงาน (Dates) สำหรับใช้ใน Modal
        // (ส่งไปทั้งหมดแล้วไป Filter ฝั่ง Client หรือจะดึงแยกเมื่อกดก็ได้)
        const [allDates] = await dbPool.query(`
            SELECT NS.UserID, DATE_FORMAT(NS.Nurse_Date, '%d %b') as d, S.ShiftName as type
            FROM NurseSchedule NS
            JOIN Shift S ON NS.Shift_id = S.Shift_id
            WHERE MONTH(NS.Nurse_Date) = ? AND YEAR(NS.Nurse_Date) = ?
        `, [month, year]);

        // ประกอบข้อมูลกลับไป
        res.json({
            success: true,
            monthName: moment(`${year}-${month}-01`).format('MMMM'),
            wardTotal: wardStats[0].total || 0,
            totalM: wardStats[0].morning || 0,
            totalA: wardStats[0].afternoon || 0,
            totalN: wardStats[0].night || 0,
            nurses: nurses.map(n => ({
                ...n,
                name: `${n.FirstName} ${n.LastName}`,
                img: n.ProfileImage || `https://ui-avatars.com/api/?name=${n.FirstName}`,
                status: n.n > 5 ? 'ดึกหนัก' : n.a > 10 ? 'บ่ายหนัก' : 'ปกติ',
                dates: allDates.filter(d => d.UserID === n.UserID)
            }))
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
app.post('/api/force-change-password', authenticateToken, async (req, res) => {
    const { userId, newPassword } = req.body;
    if (req.user.userId != userId) {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, message: "รหัสผ่านต้องมีความยาวอย่างน้อย 6 ตัวอักษร" });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await dbPool.query(
            "UPDATE User SET PasswordHash = ?, MustChangePassword = 0 WHERE UserID = ?", 
            [hashedPassword, userId]
        );

        res.json({ success: true, message: "เปลี่ยนรหัสผ่านสำเร็จ เข้าใช้งานระบบได้เลยครับ" });

    } catch (err) {
        console.error("Force Change Password Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
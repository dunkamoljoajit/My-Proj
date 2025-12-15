// backend/seed.js
require('dotenv').config(); // ✅ แก้ตรงนี้: ลบ path ออก เพื่อให้หาไฟล์ในโฟลเดอร์เดียวกัน

const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function seedHeadNurse() {
  let connection;
  try {
    // 1. เชื่อมต่อ Database
    connection = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_DATABASE,
        port: process.env.DB_PORT || 4000,
        ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
    });
    console.log('🔌 Connected to Database');
    // 2. ข้อมูล Head Nurse
    const plainPassword = 'admin1234';
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    const headNurse = {
        FirstName: 'ปรเมศว์',     
        LastName: 'หิรัญเจริญกุล',    
        Email: 'dungkamoljoajit2547@gmail.com',
        PasswordHash: hashedPassword, 
        RoleID: 1                 
    };

    // 3. เช็คจาก Email
    const [rows] = await connection.execute(
        'SELECT * FROM User WHERE Email = ?', 
        [headNurse.Email]
    );

    if (rows.length > 0) {
        console.log('⚠️  Head Nurse already exists. Skipping...');
    } else {
        // 4. Insert
        const sql = `
            INSERT INTO User (FirstName, LastName, Email, PasswordHash, RoleID)
            VALUES (?, ?, ?, ?, ?)
        `;
        
        await connection.execute(sql, [
            headNurse.FirstName,
            headNurse.LastName,
            headNurse.Email,
            headNurse.PasswordHash,
            headNurse.RoleID
        ]);
        
        console.log('✅ Created Head Nurse successfully!');
        console.log(`👉 Email: ${headNurse.Email}`);
        console.log(`👉 Password: ${plainPassword}`);
    }

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    if (connection) await connection.end();
  }
}

seedHeadNurse();
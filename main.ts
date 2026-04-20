import { Application, Router } from "https://deno.land/x/oak@14.2.0/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import * as jwt from "https://deno.land/x/djwt@v2.8/mod.ts";
import { getNumericDate } from "https://deno.land/x/djwt@v2.8/mod.ts";
import { Client } from "https://deno.land/x/mysql@v2.12.1/mod.ts";

// ===================== 修复1：环境变量校验 =====================
const env = Deno.env.toObject();
const requiredEnv = [
  "JWT_SECRET", "ADMIN_PASSWORD", "AES_KEY",
  "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_DATABASE",
  "LATEST_VERSION", "FORCE_UPDATE", "DOWNLOAD_URL", "UPDATE_DESC"
];

for (const key of requiredEnv) {
  if (!env[key]) {
    console.error(`❌ 缺失环境变量: ${key}`);
    Deno.exit(1);
  }
}

const JWT_SECRET = env.JWT_SECRET;
const JWT_EXPIRES_IN = 604800;
const ADMIN_PASSWORD = env.ADMIN_PASSWORD;
const AES_KEY = env.AES_KEY;
const CODE_EXPIRE_DAYS = 30;

// 全局变量
let client: Client | null = null;
let jwtKey: CryptoKey | null = null;
let isInitialized = false;
let initPromise: Promise<void> | null = null;

// ===================== 修复2：JWT密钥初始化 =====================
async function getJwtKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  return await crypto.subtle.importKey(
    "raw", keyData,
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign", "verify"]
  );
}

// ===================== 修复3：Deno原生AES解密（替换node:crypto） =====================
// 解密映射
const DECODE_MAP = {
  'KA': 'a', 'KB': 'b', 'KC': 'c', 'KD': 'd', 'KE': 'e',
  'KF': 'f', 'KG': 'g', 'KH': 'h', 'KI': 'i', 'KJ': 'j',
  'KK': 'k', 'KL': 'l', 'KM': 'm', 'KN': 'n', 'KO': 'o',
  'KP': 'p', 'KQ': 'q', 'KR': 'r', 'KS': 's', 'KT': 't',
  'KU': 'u', 'KV': 'v', 'KW': 'w', 'KX': 'x', 'KY': 'y',
  'KZ': 'z', 'LA': '+', 'LB': '/', 'LC': '='
};

// AES-128-ECB 解密（Deno原生Web Crypto实现，兼容Deno Deploy）
async function aesDecrypt(encryptedText: string) {
  try {
    let processedText = encryptedText.replace(/-/g, '');
    // 替换映射字符
    const entries = Object.entries(DECODE_MAP).sort((a, b) => b[0].length - a[0].length);
    for (const [key, value] of entries) {
      processedText = processedText.split(key).join(value);
    }

    // base64转字节
    const encryptedData = Uint8Array.from(atob(processedText), c => c.charCodeAt(0));
    const keyBytes = new TextEncoder().encode(AES_KEY.padEnd(16, '\0').slice(0, 16));

    // 导入AES密钥
    const key = await crypto.subtle.importKey(
      "raw", keyBytes,
      { name: "AES-ECB" },
      false, ["decrypt"]
    );

    // 解密
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-ECB" },
      key,
      encryptedData
    );

    // 转字符串并去除PKCS7填充
    const decoder = new TextDecoder();
    let decrypted = decoder.decode(decryptedData);
    const pad = decrypted.charCodeAt(decrypted.length - 1);
    decrypted = decrypted.slice(0, -pad);
    return decrypted;
  } catch (e) {
    console.error('❌ 解密失败：', e);
    return null;
  }
}

// 激活码解析
async function parseActivateCode(code: string) {
  const plainText = await aesDecrypt(code); // 改为异步
  if (!plainText) return { success: false, error: '激活码格式错误' };
  const parts = plainText.split('|');
  if (parts.length !== 5) return { success: false, error: '激活码格式无效' };
  const [userId, deviceFingerprint, days, timestamp] = parts;
  const generateTime = new Date(parseInt(timestamp) * 1000);
  const expireTime = new Date(generateTime.getTime() + CODE_EXPIRE_DAYS * 24 * 60 * 60 * 1000);
  if (new Date() > expireTime) return { success: false, error: '激活码已过期' };
  return {
    success: true,
    userId: parseInt(userId),
    deviceFingerprint,
    days: parseInt(days),
    generateTime
  };
}

// ===================== 修复4：数据库初始化（带重试，无超时） =====================
async function initDB() {
  if (!client) return;
  try {
    console.log('🔧 正在初始化数据库表...');
    await client.execute(`CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY,username VARCHAR(50) NOT NULL UNIQUE,password VARCHAR(255) NOT NULL,is_premium BOOLEAN DEFAULT FALSE,premium_expiry DATETIME NULL,security_question VARCHAR(255) NULL,security_answer VARCHAR(255) NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    await client.execute(`CREATE TABLE IF NOT EXISTS items (id VARCHAR(100) PRIMARY KEY,user_id INT NOT NULL,name VARCHAR(255) NOT NULL,price DECIMAL(20,2) NOT NULL,purchase_date BIGINT NOT NULL,category_name VARCHAR(100),icon_code INT,expect_use_years INT NULL,residual_rate DECIMAL(5,4) NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    await client.execute(`CREATE TABLE IF NOT EXISTS category_mappings (id INT AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,keyword VARCHAR(100) NOT NULL,category_name VARCHAR(100) NOT NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,UNIQUE KEY unique_keyword_per_user (user_id, keyword))`);
    await client.execute(`CREATE TABLE IF NOT EXISTS used_codes (id INT AUTO_INCREMENT PRIMARY KEY,activate_code VARCHAR(500) NOT NULL UNIQUE,user_id INT NOT NULL,device_fingerprint VARCHAR(200) NOT NULL,days INT NOT NULL,used_at DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    await client.execute(`CREATE TABLE IF NOT EXISTS unbind_applications (id INT AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,username VARCHAR(50) NOT NULL,old_device_fingerprint VARCHAR(200) NOT NULL,new_device_fingerprint VARCHAR(200) NOT NULL,status TINYINT DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,handle_at DATETIME NULL,FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    
    try {
      await client.execute('SELECT 1 FROM user_checkin LIMIT 1');
    } catch {
      await client.execute(`CREATE TABLE user_checkin (id INT AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL UNIQUE,consecutive_check_in_days INT DEFAULT 0,total_check_in_days INT DEFAULT 0,longest_streak INT DEFAULT 0,re_sign_cards INT DEFAULT 0,last_check_in_date DATETIME NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    }
    console.log('✅ 数据库表初始化完成');
  } catch (err) {
    console.error('❌ 数据库初始化失败:', err);
    throw err;
  }
}

// 全局初始化（带重试，无超时限制）
async function initAll() {
  if (isInitialized) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    let retries = 5;
    while (retries > 0) {
      try {
        // 1. 初始化JWT
        jwtKey = await getJwtKey(JWT_SECRET);
        console.log("✅ JWT密钥初始化成功");

        // 2. 连接MySQL
        client = await new Client().connect({
          hostname: env.DB_HOST,
          port: Number(env.DB_PORT),
          username: env.DB_USER,
          password: env.DB_PASSWORD,
          db: env.DB_DATABASE,
          timeout: 30000 // 延长数据库超时
        });
        console.log("✅ MySQL连接成功");

        // 3. 初始化数据库表
        await initDB();

        isInitialized = true;
        console.log("✅ 全局初始化完成！服务正常运行");
        return;
      } catch (err) {
        retries--;
        console.error(`❌ 初始化失败，剩余重试次数 ${retries}:`, err);
        if (retries === 0) throw new Error("初始化最终失败");
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
    }
  })();

  return initPromise;
}

// ===================== JWT中间件 =====================
async function authenticateToken(ctx: any, next: () => Promise<void>) {
  const authHeader = ctx.request.headers.get('authorization');
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    ctx.response.status = 401;
    ctx.response.body = { success: false, message: '请先登录' };
    return;
  }
  try {
    if (!jwtKey) throw new Error("JWT未初始化");
    const payload = await jwt.verify(token, jwtKey);
    ctx.state.user = payload;
    await next();
  } catch (err) {
    console.error("❌ Token验证失败:", err);
    ctx.response.status = 403;
    ctx.response.body = { success: false, message: '登录已过期' };
  }
}

// ===================== 路由（全部保持不变） =====================
const router = new Router();

// 注册
router.post('/api/register', async (ctx) => {
  const { username, password } = await ctx.request.json();
  if (!username || !password || username.length < 4 || username.length > 16 || password.length < 8) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
    if (!client) throw new Error("数据库未连接");
    await client.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, password]);
    ctx.response.body = { success: true, message: '注册成功' };
  } catch (err) {
    ctx.response.body = { success: false, message: '用户名已存在' };
  }
});

// 登录
router.post('/api/login', async (ctx) => {
  const { username, password } = await ctx.request.json();
  if (!username || !password) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
    if (!client || !jwtKey) throw new Error("服务未初始化");
    const [rows] = await client.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (!rows.length) {
      ctx.response.body = { success: false, message: '用户名或密码错误' };
      return;
    }
    const user = rows[0];
    if (password !== user.password) {
      ctx.response.body = { success: false, message: '用户名或密码错误' };
      return;
    }
    let isPremium = user.is_premium;
    if (user.premium_expiry && new Date() > new Date(user.premium_expiry)) isPremium = false;
    
    const token = await jwt.create(
      { alg: "HS256" },
      { userId: user.id, username: user.username, exp: getNumericDate(JWT_EXPIRES_IN) },
      jwtKey
    );
    
    ctx.response.body = {
      success: true, token, userId: user.id, username: user.username,
      isPremium: !!isPremium, expiryDate: user.premium_expiry ? new Date(user.premium_expiry).toISOString() : null,
      securityQuestion: user.security_question
    };
  } catch (err) {
    console.error("❌ 登录接口错误:", err);
    ctx.response.body = { success: false, message: '登录失败' };
  }
});

// 同步数据 POST
router.post('/api/sync', authenticateToken, async (ctx) => {
  const { items, mappings } = await ctx.request.json();
  const userId = ctx.state.user.userId;
  if (!client) return ctx.response.body = { success: false, message: '数据库未连接' };
  const conn = await client.getConnection();
  try {
    await conn.execute('DELETE FROM items WHERE user_id = ?', [userId]);
    await conn.execute('DELETE FROM category_mappings WHERE user_id = ?', [userId]);
    if (items && Array.isArray(items)) {
      for (const item of items) {
        try {
          const price = parseFloat(item.price) || 0;
          const purchaseDate = parseInt(item.purchaseDateMillis) || Date.now();
          const expectUseYears = item.expectUseYears ? parseInt(item.expectUseYears) : null;
          const residualRate = item.residualRate ? parseFloat(item.residualRate) : null;
          await conn.execute(
            'INSERT INTO items (id, user_id, name, price, purchase_date, category_name, icon_code, expect_use_years, residual_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [item.id, userId, item.name || '未命名', price, purchaseDate, item.customCategoryName || null, item.customIconCodePoint || null, expectUseYears, residualRate]
          );
        } catch (e) {}
      }
    }
    if (mappings && Array.isArray(mappings)) {
      for (const m of mappings) {
        try {
          await conn.execute('INSERT INTO category_mappings (user_id, keyword, category_name) VALUES (?, ?, ?)', [userId, m.keyword, m.categoryName]);
        } catch (e) {}
      }
    }
    ctx.response.body = { success: true, message: '同步成功' };
  } catch (err) {
    ctx.response.body = { success: false, message: '同步失败' };
  } finally {
    conn.release();
  }
});

// 同步数据 GET
router.get('/api/sync', authenticateToken, async (ctx) => {
  const userId = ctx.state.user.userId;
  try {
    if (!client) throw new Error("数据库未连接");
    const [itemRows] = await client.execute('SELECT * FROM items WHERE user_id = ?', [userId]);
    const [mappingRows] = await client.execute('SELECT keyword, category_name FROM category_mappings WHERE user_id = ?', [userId]);
    const [userRows] = await client.execute('SELECT is_premium, premium_expiry, security_question FROM users WHERE id = ?', [userId]);
    if (!userRows.length) {
      ctx.response.body = { success: false, message: '用户不存在', items: [], mappings: [] };
      return;
    }
    const user = userRows[0];
    let isPremium = user.is_premium;
    if (user.premium_expiry && new Date() > new Date(user.premium_expiry)) isPremium = false;
    ctx.response.body = {
      success: true, items: itemRows, mappings: mappingRows,
      isPremium: !!isPremium, premiumExpiryDate: user.premium_expiry ? new Date(user.premium_expiry).toISOString() : null,
      securityQuestion: user.security_question
    };
  } catch (err) {
    ctx.response.body = { success: false, message: '获取失败', items: [], mappings: [] };
  }
});

// 激活会员
router.post('/api/pay/activate', authenticateToken, async (ctx) => {
  const { activateCode, deviceFingerprint } = await ctx.request.json();
  const userId = ctx.state.user.userId;
  if (!client) return ctx.response.body = { success: false, message: '数据库未连接' };
  const conn = await client.getConnection();
  try {
    const codeInfo = await parseActivateCode(activateCode); // 异步解密
    if (!codeInfo.success) {
      ctx.response.body = { success: false, message: codeInfo.error };
      return;
    }
    if (codeInfo.userId !== userId) {
      ctx.response.body = { success: false, message: '激活码不属于当前账号' };
      return;
    }
    const shortDev = deviceFingerprint.substring(0, 16);
    if (codeInfo.deviceFingerprint !== shortDev) {
      ctx.response.body = { success: false, message: '激活码与设备不匹配' };
      return;
    }
    const [used] = await conn.execute('SELECT * FROM used_codes WHERE activate_code = ?', [activateCode]);
    if (used.length) {
      ctx.response.body = { success: false, message: '激活码已使用' };
      return;
    }
    const [userRows] = await conn.execute('SELECT * FROM users WHERE id = ?', [userId]);
    const user = userRows[0];
    let newExpiry = new Date();
    if (user.is_premium && user.premium_expiry && new Date(user.premium_expiry) > new Date()) {
      newExpiry = new Date(user.premium_expiry);
    }
    newExpiry.setDate(newExpiry.getDate() + codeInfo.days);
    await conn.execute('UPDATE users SET is_premium = 1, premium_expiry = ? WHERE id = ?', [newExpiry, userId]);
    await conn.execute('INSERT INTO used_codes (activate_code, user_id, device_fingerprint, days) VALUES (?, ?, ?, ?)', [activateCode, userId, deviceFingerprint, codeInfo.days]);
    ctx.response.body = { success: true, message: `激活成功！延长${codeInfo.days}天`, expiryDate: newExpiry.toISOString(), days: codeInfo.days };
  } catch (err) {
    ctx.response.body = { success: false, message: '激活失败' };
  } finally {
    conn.release();
  }
});

// 设备解绑
router.post('/api/device/unbind', authenticateToken, async (ctx) => {
  const { newDeviceFingerprint } = await ctx.request.json();
  const userId = ctx.state.user.userId;
  const username = ctx.state.user.username;
  try {
    if (!client) throw new Error("数据库未连接");
    const [codeRows] = await client.execute('SELECT device_fingerprint FROM used_codes WHERE user_id = ? ORDER BY used_at DESC LIMIT 1', [userId]);
    if (!codeRows.length) {
      ctx.response.body = { success: false, message: '未找到绑定记录' };
      return;
    }
    const oldDev = codeRows[0].device_fingerprint;
    await client.execute('INSERT INTO unbind_applications (user_id, username, old_device_fingerprint, new_device_fingerprint) VALUES (?, ?, ?, ?)', [userId, username, oldDev, newDeviceFingerprint]);
    ctx.response.body = { success: true, message: '解绑申请已提交' };
  } catch (err) {
    ctx.response.body = { success: false, message: '提交失败' };
  }
});

// 管理员-解绑列表
router.get('/api/admin/unbind/list', async (ctx) => {
  const adminPwd = ctx.request.headers.get('admin-password');
  if (!adminPwd || adminPwd !== ADMIN_PASSWORD) {
    ctx.response.status = 403;
    ctx.response.body = { success: false, message: '无权访问' };
    return;
  }
  try {
    if (!client) throw new Error("数据库未连接");
    const [rows] = await client.execute('SELECT * FROM unbind_applications ORDER BY created_at DESC');
    ctx.response.body = { success: true, data: rows };
  } catch (err) {
    ctx.response.body = { success: false, message: '查询失败' };
  }
});

// 管理员-处理解绑
router.post('/api/admin/unbind/handle', async (ctx) => {
  const adminPwd = ctx.request.headers.get('admin-password');
  if (!adminPwd || adminPwd !== ADMIN_PASSWORD) {
    ctx.response.status = 403;
    ctx.response.body = { success: false, message: '无权访问' };
    return;
  }
  const { id, status } = await ctx.request.json();
  try {
    if (!client) throw new Error("数据库未连接");
    await client.execute('UPDATE unbind_applications SET status = ?, handle_at = NOW() WHERE id = ?', [status, id]);
    if (status === 1) {
      const [apply] = await client.execute('SELECT user_id FROM unbind_applications WHERE id = ?', [id]);
      const uid = apply[0].user_id;
      await client.execute('DELETE FROM used_codes WHERE user_id = ?', [uid]);
    }
    ctx.response.body = { success: true, message: '审核完成' };
  } catch (err) {
    ctx.response.body = { success: false, message: '操作失败' };
  }
});

// 用户状态
router.get('/api/user/status', authenticateToken, async (ctx) => {
  const userId = ctx.state.user.userId;
  try {
    if (!client) throw new Error("数据库未连接");
    const [rows] = await client.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (!rows.length) {
      ctx.response.body = { success: false, message: '用户不存在' };
      return;
    }
    const user = rows[0];
    let isPremium = user.is_premium;
    if (user.premium_expiry && new Date() > new Date(user.premium_expiry)) isPremium = false;
    ctx.response.body = {
      success: true, userId: user.id, username: user.username,
      isPremium: !!isPremium, expiryDate: user.premium_expiry ? new Date(user.premium_expiry).toISOString() : null,
      securityQuestion: user.security_question
    };
  } catch (err) {
    ctx.response.body = { success: false, message: '服务器错误' };
  }
});

// 修改用户名
router.post('/api/user/change-username', authenticateToken, async (ctx) => {
  const { newUsername } = await ctx.request.json();
  const userId = ctx.state.user.userId;
  if (!newUsername || newUsername.length < 4 || newUsername.length > 16) {
    ctx.response.body = { success: false, message: '用户名长度错误' };
    return;
  }
  try {
    if (!client) throw new Error("数据库未连接");
    const [existing] = await client.execute('SELECT id FROM users WHERE username = ? AND id != ?', [newUsername, userId]);
    if (existing.length) {
      ctx.response.body = { success: false, message: '用户名已占用' };
      return;
    }
    await client.execute('UPDATE users SET username = ? WHERE id = ?', [newUsername, userId]);
    ctx.response.body = { success: true, message: '修改成功', newUsername };
  } catch (err) {
    ctx.response.body = { success: false, message: '修改失败' };
  }
});

// 修改密码
router.post('/api/user/change-password', authenticateToken, async (ctx) => {
  const { oldPassword, newPassword } = await ctx.request.json();
  const userId = ctx.state.user.userId;
  if (!oldPassword || !newPassword || newPassword.length < 8) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
    if (!client) throw new Error("数据库未连接");
    const [rows] = await client.execute('SELECT password FROM users WHERE id = ?', [userId]);
    if (!rows.length) {
      ctx.response.body = { success: false, message: '用户不存在' };
      return;
    }
    const currentPwd = rows[0].password;
    if (oldPassword !== currentPwd) {
      ctx.response.body = { success: false, message: '原密码错误' };
      return;
    }
    await client.execute('UPDATE users SET password = ? WHERE id = ?', [newPassword, userId]);
    ctx.response.body = { success: true, message: '修改成功，请重新登录' };
  } catch (err) {
    ctx.response.body = { success: false, message: '修改失败' };
  }
});

// 设置密保
router.post('/api/user/security-question', authenticateToken, async (ctx) => {
  const { question, answer } = await ctx.request.json();
  const userId = ctx.state.user.userId;
  if (!question || !answer) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
    if (!client) throw new Error("数据库未连接");
    await client.execute('UPDATE users SET security_question = ?, security_answer = ? WHERE id = ?', [question, answer, userId]);
    ctx.response.body = { success: true, message: '设置成功' };
  } catch (err) {
    ctx.response.body = { success: false, message: '设置失败' };
  }
});

// 重置密码
router.post('/api/user/reset-password', async (ctx) => {
  const { username, answer, newPassword } = await ctx.request.json();
  if (!username || !answer || !newPassword || newPassword.length < 8) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
    if (!client) throw new Error("数据库未连接");
    const [rows] = await client.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (!rows.length) {
      ctx.response.body = { success: false, message: '用户不存在' };
      return;
    }
    const user = rows[0];
    if (!user.security_question) {
      ctx.response.body = { success: false, message: '未设置密保' };
      return;
    }
    if (answer !== user.security_answer) {
      ctx.response.body = { success: false, message: '密保答案错误' };
      return;
    }
    await client.execute('UPDATE users SET password = ? WHERE id = ?', [newPassword, user.id]);
    ctx.response.body = { success: true, message: '重置成功，请登录' };
  } catch (err) {
    ctx.response.body = { success: false, message: '重置失败' };
  }
});

// 版本检查
router.get('/api/version/check', (ctx) => {
  ctx.response.body = {
    success: true,
    latestVersion: env.LATEST_VERSION,
    forceUpdate: env.FORCE_UPDATE,
    downloadUrl: env.DOWNLOAD_URL,
    updateDesc: env.UPDATE_DESC,
  };
});

// 获取密保问题
router.get('/api/user/security-question/:username', async (ctx) => {
  const { username } = ctx.params;
  try {
    if (!client) throw new Error("数据库未连接");
    const [rows] = await client.execute('SELECT security_question FROM users WHERE username = ?', [username]);
    if (!rows.length) {
      ctx.response.body = { success: false, message: '用户不存在' };
      return;
    }
    const user = rows[0];
    if (!user.security_question) {
      ctx.response.body = { success: false, message: '未设置密保' };
      return;
    }
    ctx.response.body = { success: true, securityQuestion: user.security_question };
  } catch (err) {
    ctx.response.body = { success: false, message: '服务器错误' };
  }
});

// 获取打卡数据
router.get('/api/user/checkin', authenticateToken, async (ctx) => {
  const userId = ctx.state.user.userId;
  try {
    if (!client) throw new Error("数据库未连接");
    const [userRows] = await client.execute('SELECT is_premium FROM users WHERE id = ?', [userId]);
    if (!userRows.length || !userRows[0].is_premium) {
      ctx.response.status = 403;
      ctx.response.body = { success: false, message: '仅限会员' };
      return;
    }
    const [rows] = await client.execute('SELECT * FROM user_checkin WHERE user_id = ?', [userId]);
    if (!rows.length) {
      ctx.response.body = { success: true, data: null };
      return;
    }
    const r = rows[0];
    ctx.response.body = {
      success: true,
      data: {
        consecutiveCheckInDays: r.consecutive_check_in_days,
        totalCheckInDays: r.total_check_in_days,
        longestStreak: r.longest_streak,
        reSignCards: r.re_sign_cards,
        lastCheckInDate: r.last_check_in_date ? new Date(r.last_check_in_date).toISOString() : null
      }
    };
  } catch (err) {
    ctx.response.body = { success: false, message: '服务器错误' };
  }
});

// 上传打卡数据
router.post('/api/user/checkin', authenticateToken, async (ctx) => {
  const data = await ctx.request.json();
  const userId = ctx.state.user.userId;
  try {
    if (!client) throw new Error("数据库未连接");
    const [userRows] = await client.execute('SELECT is_premium FROM users WHERE id = ?', [userId]);
    if (!userRows.length || !userRows[0].is_premium) {
      ctx.response.status = 403;
      ctx.response.body = { success: false, message: '仅限会员' };
      return;
    }
    const [existing] = await client.execute('SELECT id FROM user_checkin WHERE user_id = ?', [userId]);
    if (existing.length) {
      await client.execute(`UPDATE user_checkin SET consecutive_check_in_days = ?, total_check_in_days = ?, longest_streak = ?, re_sign_cards = ?, last_check_in_date = ? WHERE user_id = ?`,
        [data.consecutiveCheckInDays || 0, data.totalCheckInDays || 0, data.longestStreak || 0, data.reSignCards || 0, data.lastCheckInDate ? new Date(data.lastCheckInDate) : null, userId]);
    } else {
      await client.execute(`INSERT INTO user_checkin (user_id, consecutive_check_in_days, total_check_in_days, longest_streak, re_sign_cards, last_check_in_date) VALUES (?, ?, ?, ?, ?, ?)`,
        [userId, data.consecutiveCheckInDays || 0, data.totalCheckInDays || 0, data.longestStreak || 0, data.reSignCards || 0, data.lastCheckInDate ? new Date(data.lastCheckInDate) : null]);
    }
    ctx.response.body = { success: true, message: '同步成功' };
  } catch (err) {
    ctx.response.body = { success: false, message: '同步失败' };
  }
});

// ===================== 修复5：服务启动初始化（无超时中间件） =====================
// 服务启动时直接初始化
await initAll().catch(err => {
  console.error("❌ 服务启动初始化失败:", err);
  Deno.exit(1);
});

// 服务配置
const app = new Application();
app.use(oakCors({ origin: '*' }));
app.use(router.routes());
app.use(router.allowedMethods());

// 404
app.use((ctx) => {
  ctx.response.status = 404;
  ctx.response.body = { success: false, message: '接口不存在' };
});

// Deno Deploy 导出
export default {
  fetch: app.fetch,
};

import { Application, Router } from "https://deno.land/x/oak@14.2.0/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import * as jwt from "https://deno.land/x/djwt@v2.8/mod.ts";
import { Client } from "https://deno.land/x/mysql@v2.12.1/mod.ts";
import { createDecipheriv, createCipheriv } from "node:crypto";

// 环境变量
const env = Deno.env.toObject();
const JWT_SECRET = env.JWT_SECRET;
const JWT_EXPIRES_IN = Number(env.JWT_EXPIRES_IN);
const ADMIN_PASSWORD = env.ADMIN_PASSWORD;
const AES_KEY = env.AES_KEY;
const CODE_EXPIRE_DAYS = 30;

// 数据库连接
const client = await new Client().connect({
  hostname: env.DB_HOST,
  port: Number(env.DB_PORT),
  username: env.DB_USER,
  password: env.DB_PASSWORD,
  db: env.DB_DATABASE,
});

// 解密映射
const DECODE_MAP = {
  'KA': 'a', 'KB': 'b', 'KC': 'c', 'KD': 'd', 'KE': 'e',
  'KF': 'f', 'KG': 'g', 'KH': 'h', 'KI': 'i', 'KJ': 'j',
  'KK': 'k', 'KL': 'l', 'KM': 'm', 'KN': 'n', 'KO': 'o',
  'KP': 'p', 'KQ': 'q', 'KR': 'r', 'KS': 's', 'KT': 't',
  'KU': 'u', 'KV': 'v', 'KW': 'w', 'KX': 'x', 'KY': 'y',
  'KZ': 'z', 'LA': '+', 'LB': '/', 'LC': '='
};

// AES解密
function aesDecrypt(encryptedText: string) {
  try {
    let processedText = encryptedText.replace(/-/g, '');
    for (const [key, value] of Object.entries(DECODE_MAP).sort((a, b) => b[0].length - a[0].length)) {
      processedText = processedText.split(key).join(value);
    }
    const decipher = createDecipheriv('aes-128-ecb', Buffer.from(AES_KEY, 'utf8'), null);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(processedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('❌ 解密失败：', e);
    return null;
  }
}

// 激活码解析
function parseActivateCode(code: string) {
  const plainText = aesDecrypt(code);
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

// 初始化数据库
async function initDB() {
  try {
    console.log('🔧 正在检查数据库...');
    await client.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        is_premium BOOLEAN DEFAULT FALSE,
        premium_expiry DATETIME NULL,
        security_question VARCHAR(255) NULL,
        security_answer VARCHAR(255) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await client.execute(`
      CREATE TABLE IF NOT EXISTS items (
        id VARCHAR(100) PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(20,2) NOT NULL,
        purchase_date BIGINT NOT NULL,
        category_name VARCHAR(100),
        icon_code INT,
        expect_use_years INT NULL,
        residual_rate DECIMAL(5,4) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await client.execute(`
      CREATE TABLE IF NOT EXISTS category_mappings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        keyword VARCHAR(100) NOT NULL,
        category_name VARCHAR(100) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY unique_keyword_per_user (user_id, keyword)
      )
    `);
    await client.execute(`
      CREATE TABLE IF NOT EXISTS used_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        activate_code VARCHAR(500) NOT NULL UNIQUE,
        user_id INT NOT NULL,
        device_fingerprint VARCHAR(200) NOT NULL,
        days INT NOT NULL,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await client.execute(`
      CREATE TABLE IF NOT EXISTS unbind_applications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        username VARCHAR(50) NOT NULL,
        old_device_fingerprint VARCHAR(200) NOT NULL,
        new_device_fingerprint VARCHAR(200) NOT NULL,
        status TINYINT DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        handle_at DATETIME NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    try {
      await client.execute('SELECT * FROM user_checkin LIMIT 1');
    } catch (e) {
      await client.execute(`
        CREATE TABLE user_checkin (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL UNIQUE,
          consecutive_check_in_days INT DEFAULT 0,
          total_check_in_days INT DEFAULT 0,
          longest_streak INT DEFAULT 0,
          re_sign_cards INT DEFAULT 0,
          last_check_in_date DATETIME NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);
    }
    console.log('✅ 数据库初始化完成');
  } catch (err) {
    console.error('❌ 数据库初始化失败:', err);
  }
}

// JWT中间件
async function authenticateToken(ctx: any, next: () => Promise<void>) {
  const authHeader = ctx.request.headers.get('authorization');
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    ctx.response.status = 401;
    ctx.response.body = { success: false, message: '请先登录' };
    return;
  }
  try {
    const payload = await jwt.verify(token, JWT_SECRET);
    ctx.state.user = payload;
    await next();
  } catch (err) {
    ctx.response.status = 403;
    ctx.response.body = { success: false, message: '登录已过期' };
  }
}

// 路由
const router = new Router();

// 注册
router.post('/api/register', async (ctx) => {
  const { username, password } = await ctx.request.body().value;
  if (!username || !password || username.length < 4 || username.length > 16 || password.length < 8) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
    await client.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, password]);
    ctx.response.body = { success: true, message: '注册成功' };
  } catch (err) {
    ctx.response.body = { success: false, message: '用户名已存在' };
  }
});

// 登录
router.post('/api/login', async (ctx) => {
  const { username, password } = await ctx.request.body().value;
  if (!username || !password) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
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
    const token = await jwt.create({ alg: 'HS256', exp: Date.now() / 1000 + JWT_EXPIRES_IN }, { userId: user.id, username: user.username }, JWT_SECRET);
    ctx.response.body = {
      success: true, token, userId: user.id, username: user.username,
      isPremium: !!isPremium, expiryDate: user.premium_expiry ? new Date(user.premium_expiry).toISOString() : null,
      securityQuestion: user.security_question
    };
  } catch (err) {
    ctx.response.body = { success: false, message: '登录失败' };
  }
});

// 同步数据
router.post('/api/sync', authenticateToken, async (ctx) => {
  const { items, mappings } = await ctx.request.body().value;
  const userId = ctx.state.user.userId;
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

router.get('/api/sync', authenticateToken, async (ctx) => {
  const userId = ctx.state.user.userId;
  try {
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
  const { activateCode, deviceFingerprint } = await ctx.request.body().value;
  const userId = ctx.state.user.userId;
  const conn = await client.getConnection();
  try {
    const codeInfo = parseActivateCode(activateCode);
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
  const { newDeviceFingerprint } = await ctx.request.body().value;
  const userId = ctx.state.user.userId;
  const username = ctx.state.user.username;
  try {
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

// 管理员接口
router.get('/api/admin/unbind/list', async (ctx) => {
  const adminPwd = ctx.request.headers.get('admin-password');
  if (!adminPwd || adminPwd !== ADMIN_PASSWORD) {
    ctx.response.status = 403;
    ctx.response.body = { success: false, message: '无权访问' };
    return;
  }
  try {
    const [rows] = await client.execute('SELECT * FROM unbind_applications ORDER BY created_at DESC');
    ctx.response.body = { success: true, data: rows };
  } catch (err) {
    ctx.response.body = { success: false, message: '查询失败' };
  }
});

router.post('/api/admin/unbind/handle', async (ctx) => {
  const adminPwd = ctx.request.headers.get('admin-password');
  if (!adminPwd || adminPwd !== ADMIN_PASSWORD) {
    ctx.response.status = 403;
    ctx.response.body = { success: false, message: '无权访问' };
    return;
  }
  const { id, status } = await ctx.request.body().value;
  try {
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
  const { newUsername } = await ctx.request.body().value;
  const userId = ctx.state.user.userId;
  if (!newUsername || newUsername.length < 4 || newUsername.length > 16) {
    ctx.response.body = { success: false, message: '用户名长度错误' };
    return;
  }
  try {
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
  const { oldPassword, newPassword } = await ctx.request.body().value;
  const userId = ctx.state.user.userId;
  if (!oldPassword || !newPassword || newPassword.length < 8) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
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
  const { question, answer } = await ctx.request.body().value;
  const userId = ctx.state.user.userId;
  if (!question || !answer) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
    await client.execute('UPDATE users SET security_question = ?, security_answer = ? WHERE id = ?', [question, answer, userId]);
    ctx.response.body = { success: true, message: '设置成功' };
  } catch (err) {
    ctx.response.body = { success: false, message: '设置失败' };
  }
});

// 重置密码
router.post('/api/user/reset-password', async (ctx) => {
  const { username, answer, newPassword } = await ctx.request.body().value;
  if (!username || !answer || !newPassword || newPassword.length < 8) {
    ctx.response.body = { success: false, message: '参数错误' };
    return;
  }
  try {
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

// 打卡接口
router.get('/api/user/checkin', authenticateToken, async (ctx) => {
  const userId = ctx.state.user.userId;
  try {
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

router.post('/api/user/checkin', authenticateToken, async (ctx) => {
  const userId = ctx.state.user.userId;
  const { consecutiveCheckInDays, totalCheckInDays, longestStreak, reSignCards, lastCheckInDate } = await ctx.request.body().value;
  try {
    const [userRows] = await client.execute('SELECT is_premium FROM users WHERE id = ?', [userId]);
    if (!userRows.length || !userRows[0].is_premium) {
      ctx.response.status = 403;
      ctx.response.body = { success: false, message: '仅限会员' };
      return;
    }
    const [existing] = await client.execute('SELECT id FROM user_checkin WHERE user_id = ?', [userId]);
    if (existing.length) {
      await client.execute(`
        UPDATE user_checkin 
        SET consecutive_check_in_days = ?, total_check_in_days = ?, longest_streak = ?, re_sign_cards = ?, last_check_in_date = ?
        WHERE user_id = ?
      `, [consecutiveCheckInDays || 0, totalCheckInDays || 0, longestStreak || 0, reSignCards || 0, lastCheckInDate ? new Date(lastCheckInDate) : null, userId]);
    } else {
      await client.execute(`
        INSERT INTO user_checkin (user_id, consecutive_check_in_days, total_check_in_days, longest_streak, re_sign_cards, last_check_in_date)
        VALUES (?, ?, ?, ?, ?, ?)
      `, [userId, consecutiveCheckInDays || 0, totalCheckInDays || 0, longestStreak || 0, reSignCards || 0, lastCheckInDate ? new Date(lastCheckInDate) : null]);
    }
    ctx.response.body = { success: true, message: '同步成功' };
  } catch (err) {
    ctx.response.body = { success: false, message: '同步失败' };
  }
});

// 启动服务
const app = new Application();
app.use(oakCors({ origin: '*' }));
app.use(router.routes());
app.use(router.allowedMethods());

// 404 处理（放在最后）
app.use((ctx) => {
  ctx.response.status = 404;
  ctx.response.body = { success: false, message: '接口不存在' };
});

await initDB();
console.log('🚀 Deno Deploy 服务启动成功');
await app.listen({ port: 8000 });

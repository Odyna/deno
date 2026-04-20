import { Application, Router } from "https://deno.land/x/oak@14.2.0/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import * as jwt from "https://deno.land/x/djwt@v2.8/mod.ts";
import { Client } from "https://deno.land/x/mysql@v2.12.1/mod.ts";

const env = Deno.env.toObject();
const JWT_SECRET = env.JWT_SECRET || "your-secret-key";
const JWT_EXPIRES_IN = Number(env.JWT_EXPIRES_IN) || 86400;

// 数据库连接
const client = await new Client().connect({
  hostname: env.DB_HOST,
  port: Number(env.DB_PORT || 3306),
  username: env.DB_USER,
  password: env.DB_PASSWORD,
  db: env.DB_DATABASE,
});

const router = new Router();

// ✅ 1. 登录接口（最简单的路由）
router.post("/api/login", async (ctx) => {
  try {
    const { username, password } = await ctx.request.body().value;
    const [rows] = await client.execute("SELECT * FROM users WHERE username = ?", [username]);
    
    if (!rows.length) {
      ctx.response.body = { success: false, message: "用户名或密码错误" };
      return;
    }

    const user = rows[0];
    if (password !== user.password) {
      ctx.response.body = { success: false, message: "用户名或密码错误" };
      return;
    }

    const token = await jwt.create(
      { alg: "HS256", exp: Date.now() / 1000 + JWT_EXPIRES_IN },
      { userId: user.id, username: user.username },
      JWT_SECRET
    );

    ctx.response.body = {
      success: true,
      token,
      userId: user.id,
      username: user.username,
      isPremium: !!user.is_premium,
      expiryDate: user.premium_expiry,
      securityQuestion: user.security_question,
    };
  } catch (e) {
    ctx.response.body = { success: false, message: "登录失败" };
  }
});

// ✅ 2. 版本检查接口
router.get("/api/version/check", (ctx) => {
  ctx.response.body = {
    success: true,
    latestVersion: env.LATEST_VERSION || "1.0.2",
    forceUpdate: env.FORCE_UPDATE === "true",
    downloadUrl: env.DOWNLOAD_URL || "https://www.lanzouy.com/xxxxxxx",
    updateDesc: env.UPDATE_DESC || "1. 修复已知问题",
  };
});

// ✅ 3. 404 处理（必须放在最后，而且不能用 router.all()）
router.use((ctx) => {
  ctx.response.status = 404;
  ctx.response.body = { success: false, message: "接口不存在" };
});

const app = new Application();
app.use(oakCors());
app.use(router.routes());
app.use(router.allowedMethods());

console.log("✅ Deno 服务启动成功，监听端口 8000");
await app.listen({ port: 8000 });

import { Application, Router } from "https://deno.land/x/oak@14.2.0/mod.ts";

const app = new Application();
const router = new Router();

router.get("/", (ctx) => {
  ctx.response.body = "Hello World";
});

app.use(router.routes());
app.use(router.allowedMethods());

console.log("测试服务启动");

export default {
  fetch: app.fetch,
};

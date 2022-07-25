import { Application } from "https://deno.land/x/oak@v10.6.0/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import { Router } from "https://deno.land/x/oak@v10.6.0/mod.ts";
import { time } from "https://deno.land/x/time.ts@v2.0.1/mod.ts";
import { login, register, me } from "./routes.ts";

const port = 8000;
const app = new Application();
const router = new Router();

app.use(async ({ request }, next) => {
  console.log(
    time().tz("asia/seoul").now(),
    request.ip,
    request.method,
    request.url.href
  );
  await next();
});

app.use(oakCors());
app.use(router.routes());
app.use(router.allowedMethods());

router
  .post("/api/v1/register", register)
  .post("/api/v1/login", login)
  .get("/api/v1/me", me);

app.addEventListener("listen", () => {
  console.log(`Listening on: localhost:${port}`);
});

await app.listen({ port });

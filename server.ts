import { Application } from "https://deno.land/x/oak@v10.6.0/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import { Router } from "https://deno.land/x/oak@v10.6.0/mod.ts";
import {
  create,
  getNumericDate,
  verify,
} from "https://deno.land/x/djwt@v2.7/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.0/mod.ts";
import { v1 } from "https://deno.land/std@0.147.0/uuid/mod.ts";
import { time } from "https://deno.land/x/time.ts@v2.0.1/mod.ts";
import { db } from "./db.ts";

const port = 8000;
const app = new Application();
const router = new Router();

const key = await crypto.subtle.generateKey(
  { name: "HMAC", hash: "SHA-512" },
  true,
  ["sign", "verify"]
);

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

router.post("/api/v1/register", async ({ request, response }) => {
  const { email, password, confirmPassword, displayName } = await request.body()
    .value;

  // 이메일 중복검사
  if (await db.users.findOne({ email })) {
    console.log("error, email already exists!");
    response.status = 400;
    return;
  }

  // 이름 중복검사
  if (await db.users.findOne({ displayName })) {
    console.log("error, display name already exists!");
    response.status = 400;
    return;
  }

  // todo: 비밀번호 유효성 검사

  // 비밀번호가 둘 다 동일한지 검사
  if (password != confirmPassword) {
    console.log("error, password must same!");
    response.status = 400;
    return;
  }

  const hash = await bcrypt.hash(password);
  const user = {
    id: v1.generate(),
    email: email,
    password: hash,
    displayName: displayName,
  };
  await db.users.insertOne(user);

  response.status = 200;
});

router.post("/api/v1/login", async ({ request, response }) => {
  const { email, password } = await request.body().value;
  const user = await db.users.findOne({ email });

  // 해당 이메일이 있는지 검사
  if (!user) {
    console.log("error, unregistered email!");
    response.status = 400;
    return;
  }

  // 유저정보의 비밀번호가 일치하는지 검사
  if (!(await bcrypt.compare(password, user.password as string))) {
    console.log("error, wrong password!");
    response.status = 400;
    return;
  }

  const jwt = await create(
    { alg: "HS512", typ: "JWT" },
    { id: user.id, exp: getNumericDate(60 * 1) },
    key
  );

  // console.log(jwt);
  // await verify(jwt, key);

  response.status = 200;
  response.type = "application/json";
  response.body = { token: jwt };
  // console.log(response);
});

router.get("/api/v1/me", async ({ request, response }) => {
  const token = request.headers.get("Authorization");
  // console.log(token);
  let payload;
  try {
    payload = await verify(token as string, key);
  } catch (_e) {
    console.log("error, token is not valid!");
    response.status = 401;
    return;
  }
  // const [header, payload, signature] = decode(token as string);
  // console.log(header, payload, signature);
  const user = await db.users.findOne({
    id: payload?.id as string,
  });

  if (!user) {
    console.log("error, display name not found!");
    response.status = 400;
    return;
  }

  response.status = 200;
  response.type = "application/json";
  response.body = { displayName: user.displayName };
  // console.log(response);
});

app.addEventListener("listen", () => {
  console.log(`Listening on: localhost:${port}`);
});

await app.listen({ port });

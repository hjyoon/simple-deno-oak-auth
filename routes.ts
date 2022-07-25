import { Context } from "https://deno.land/x/oak@v10.6.0/mod.ts";
import { create, Payload, verify } from "https://deno.land/x/djwt@v2.7/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.0/mod.ts";
import { v1 } from "https://deno.land/std@0.147.0/uuid/mod.ts";
import { db, User } from "./db.ts";
import { key, payload, header } from "./jwt.ts";

export const register = async ({ request, response }: Context) => {
  const { email, password, confirmPassword, displayName } = await request.body()
    .value;

  // 이메일 중복검사
  if (await db.users.findOne({ email })) {
    console.log("error, email already exists.");
    response.status = 409;
    return;
  }

  // 이름 중복검사
  if (await db.users.findOne({ displayName })) {
    console.log("error, display name already exists.");
    response.status = 409;
    return;
  }

  // todo: 비밀번호 유효성 검사

  // 비밀번호가 둘 다 동일한지 검사
  if (password != confirmPassword) {
    console.log("error, password must same.");
    response.status = 409;
    return;
  }

  const hash = await bcrypt.hash(password);
  const user: User = {
    id: v1.generate(),
    email: email,
    password: hash,
    displayName: displayName,
  };
  await db.users.insertOne(user);

  response.status = 200;
};

export const login = async ({ request, response }: Context) => {
  const { email, password } = await request.body().value;
  const user = await db.users.findOne({ email });

  // 해당 이메일이 있는지 검사
  if (!user) {
    console.log("error, unregistered email.");
    response.status = 404;
    return;
  }

  // 유저정보의 비밀번호가 일치하는지 검사
  if (!(await bcrypt.compare(password, user.password))) {
    console.log("error, wrong password!");
    response.status = 409;
    return;
  }

  const jwt = await create(header, { id: user.id, ...payload }, key);

  response.status = 200;
  response.type = "application/json";
  response.body = { token: jwt };
};

export const me = async ({ request, response }: Context) => {
  const auth_data = request.headers.get("Authorization")?.split(" ");

  if (!auth_data) {
    console.log("error, unusual Authorization value.");
    response.status = 400;
    return;
  }

  const [type, credentials] = auth_data;

  if (type != "Bearer") {
    console.log("error, only Bearer type is supported.");
    response.status = 400;
    return;
  }

  if (!credentials) {
    console.log("error, token is null!");
    response.status = 400;
    return;
  }

  let payload: Payload;
  try {
    payload = await verify(credentials, key);
  } catch (e) {
    if (e.message == "The jwt is expired.") {
      console.log("error, jwt is expired.");
      response.status = 401;
      return;
    } else {
      console.log(e.message);
    }
    response.status = 400;
    return;
  }

  const user = await db.users.findOne({
    id: (payload as Payload).id as string | number[],
  });

  if (!user) {
    console.log("error, display name not found.");
    response.status = 404;
    return;
  }

  response.status = 200;
  response.type = "application/json";
  response.body = { displayName: user.displayName };
};

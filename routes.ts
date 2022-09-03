import { Context } from "https://deno.land/x/oak@v10.6.0/mod.ts";
import {
  create,
  decode,
  Header,
  Payload,
  verify,
} from "https://deno.land/x/djwt@v2.7/mod.ts";
import { verify as verifySignature } from "https://deno.land/x/djwt@v2.7/signature.ts";
import { verify as verifyAlgorithm } from "https://deno.land/x/djwt@v2.7/algorithm.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.0/mod.ts";
import { v1 } from "https://deno.land/std@0.147.0/uuid/mod.ts";
import { db, User } from "./db.ts";
import { key, accessPayload, header, refreshPayload } from "./jwt.ts";
import { validateAuthorization } from "./utils.ts";

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

  // TODO: 비밀번호 유효성 검사

  // 비밀번호가 둘 다 동일한지 검사
  if (password != confirmPassword) {
    console.log("error, password must same.");
    response.status = 409;
    return;
  }

  const uuid = v1.generate();
  const refresh = await create(header, { id: uuid, ...refreshPayload }, key);
  const hash = await bcrypt.hash(password);
  const user: User = {
    id: uuid,
    email: email,
    password: hash,
    displayName: displayName,
    refreshToken: refresh,
  };
  await db.users.insertOne(user);

  // access 토큰 생성
  const access = await create(header, { id: user.id, ...accessPayload }, key);

  response.status = 200;
  response.type = "application/json";
  response.body = { access, refresh };
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

  // access 토큰 생성
  const access = await create(header, { id: user.id, ...accessPayload }, key);

  // refresh 토큰 생성
  const refresh = await create(header, { id: user.id, ...refreshPayload }, key);

  // 해당 유저의 db에 refresh 토큰 저장
  await db.users.updateOne({ email }, { refreshToken: refresh });

  if (!user) {
    console.log("error, user not found.");
    response.status = 404;
    return;
  }

  response.status = 200;
  response.type = "application/json";
  response.body = { access, refresh };
};

export const access = async ({ request, response }: Context) => {
  const { refresh } = await request.body().value;

  // refresh 토큰 검증
  try {
    await verify(refresh, key);
  } catch (e) {
    console.log(e.message);
    response.status = 401;
    return;
  }

  const [_refreshHeader, refreshPayload, _refreshSignature] = decode(refresh);

  // 유저 DB에 있는 refresh 토큰과 같은지 확인
  try {
    const user = await db.users.findOne({
      id: (refreshPayload as Payload).id as string | number[],
    });
    if (!user) {
      console.log("error, user not found.");
      response.status = 404;
      return;
    }
    if (refresh != user.refreshToken) {
      console.log("error, refresh tokens do not match.");
      response.status = 401;
      return;
    }
  } catch (e) {
    console.log(e.message);
    response.status = 400;
    return;
  }

  // access 토큰 검증
  try {
    const credentials = validateAuthorization(
      request.headers.get("Authorization")
    );
    const [accessHeader, _accessPayload, accessSignature] = decode(credentials);
    await verifySignature(
      accessSignature,
      key,
      (accessHeader as Header).alg,
      credentials.slice(0, credentials.lastIndexOf("."))
    );
    await verifyAlgorithm((accessHeader as Header).alg, key);
  } catch (e) {
    console.log(e.message);
    response.status = 400;
    return;
  }

  // refresh 토큰과 access 토큰이 같은 유저의 것인지 payload 내용을 비교
  try {
    if ((accessPayload as Payload).id != (refreshPayload as Payload).id) {
      throw Error("");
    }
  } catch (e) {
    console.log(e.message);
    response.status = 400;
    return;
  }

  // access 토큰 생성
  const access = await create(
    header as Header,
    { id: (refreshPayload as Payload).id, ...accessPayload },
    key
  );

  response.status = 200;
  response.type = "application/json";
  response.body = { access };
};

export const refresh = async ({ request, response }: Context) => {
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

  // refresh 토큰 생성
  const refresh = await create(
    header as Header,
    { id: (payload as Payload).id, ...refreshPayload },
    key
  );

  response.status = 200;
  response.type = "application/json";
  response.body = { refresh };
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

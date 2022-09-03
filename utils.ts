export const validateAuthorization = (s: string | null) => {
  if (!s) {
    throw Error("error, unusual Authorization value.");
  }
  const [type, credentials] = s.split(" ");

  if (type != "Bearer") {
    throw Error("error, only Bearer type is supported.");
  }

  if (!credentials) {
    throw Error("error, token is null!");
  }

  return credentials;
};

const cookieParser = require("cookie-parser");
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
const secretText = "superSecret";
const refreshSecretText = "superSuperSecret";
const posts = [
  {
    userName: "고은",
    title: "Post 1",
  },
  {
    userName: "수지",
    title: "Post 2",
  },
];
let refreshTokens = []; // 데이터베이스가 없어서 임의로 사용

app.use(express.json());
app.use(cookieParser());

app.post("/login", (req, res) => {
  const userName = req.body.userName;
  const user = { name: userName };

  // jwt 토큰 생성하기 payload, secretText
  // 유효기간 추가
  const accessToken = jwt.sign(user, secretText, { expiresIn: "30s" });

  // refresh token 생성하기
  const refreshToken = jwt.sign(user, refreshSecretText, { expiresIn: "1d" });

  refreshTokens.push(refreshToken);

  // refresh token을 쿠키에 넣어주기
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ accessToken: accessToken });
});

app.get("/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

function authMiddleware(req, res, next) {
  // 토큰을 request headers에서 가져오기
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretText, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/refresh", (req, res) => {
  // console.log("req.cookies", req.cookies);
  // 쿠키 가져오기
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(403);

  const refreshToken = cookies.jwt;
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, refreshSecretText, (err, user) => {
    if (err) return res.sendStatus(403);
    // 새로운 토큰 생성하기
    const accessToken = jwt.sign({ name: user.name }, secretText, {
      expiresIn: "30s",
    });
    res.json({ accessToken });
  });
});

const prot = 4000;
app.listen(prot, () => {
  console.log("listening on port" + prot);
});

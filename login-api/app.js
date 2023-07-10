var express = require("express");
var cors = require("cors");
var app = express();
var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();
const bcrypt = require("bcrypt");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = "Login";

app.use(cors());

const mysql = require("mysql2");
// create the connection to database
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "mydb",
});

app.post("/register", jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    connection.query(
      "INSERT INTO user  (email, password, f_name, l_name, student_no, branch, Org_s) VALUE (?, ?, ?, ?, ?,?,?)",
      [
        req.body.email,
        hash,
        req.body.f_name,
        req.body.l_name,
        req.body.student_no,
        req.body.Org_s,
        req.body.branch
      ],
      function (err, results, fields) {
        if (err) {
          res.json({ status: "err", message: err });
          return;
        }
        res.json({ status: "ok" });
      }
    );
  });
});

//สร้าง login เพื่อขอ token
app.post("/login", jsonParser, function (req, res, next) {
  connection.query(
    "SELECT * FROM user WHERE email=?",
    [req.body.email],
    function (err, user, fields) {
      if (err) {
        res.json({ status: "err", message: err });
        return;
      }
      if (user.length == 0) {
        res.json({ status: "err", message: "ไม่พบผู้ใช้งาน" });
        return;
      }
      bcrypt.compare(
        req.body.password,
        user[0].password,
        function (err, isLogin) {
          if (isLogin) {
            var token = jwt.sign({ email: user[0].email }, "secret", {
              expiresIn: "1h",
            });
            res.json({ status: "ok", message: "เข้าสู่ระบบสำเร็จ", token });
            return;
            //ถ้า login สำเร็จเราจะได้ token มา
            //{ expiresIn: '1h' } คือจะอยู่ได้แค่ 1 ชม.
            //token ใช้ในการยืนยันตัวบุคคล
          } else {
            res.json({ status: "err", message: "เข้าสู่ระบบไม่สำเร็จ" });
            return;
          }
        }
      );
    }
  );
});

//สร้าง api
app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, "secret");
    res.json({status:'ok', decoded });
  } catch (err) {
    res.json({status:'error', message: err.message });
  }
});

app.listen(3333, jsonParser, function () {
  console.log("CORS-enabled web server listening on port 3333");
});

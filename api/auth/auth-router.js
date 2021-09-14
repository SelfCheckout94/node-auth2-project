const router = require("express").Router();
const bcrypt = require("bcryptjs");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const Users = require("./../users/users-model");
const { buildToken } = require("./token-builder");

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;

  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(user.password, rounds);

  user.password = hash;

  Users.add(user)
    .then((saved) => {
      res.status(201).json(saved);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;

  Users.findBy({ username }).then(([user]) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = buildToken(user);
      res.status(200).json({
        message: `${username} is back!`,
        token,
      });
    } else {
      next({
        status: 401,
        message: "Invalid Credentials",
      });
    }
  });
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;

const express = require('express');
const jwt = require('jsonwebtoken');
const authorize = require('../middleware/auth');
const bcrypt = require('bcrypt');
const router = express.Router();
const userSchema = require("../models/users");

    router.post('/signin-user', (req, res, next) => {
        let getUser;
        userSchema
          .findOne({
            email: req.body.email,
          })
          .then((user) => {
            if (!user) {
              return res.status(401).json({
                message: 'Authentication failed',
              });
            }
            getUser = user;
            return bcrypt.compare(req.body.password, user.password);
          })
          .then((response) => {
            if (!response) {
              return res.status(401).json({
                message: 'Authentication failed',
              });
            }
            let jwtToken = jwt.sign(
              {
                email: getUser.email,
                userId: getUser._id,
              },
              'longer-secret-is-better',
              {
                expiresIn: '1h',
              }
            );
            res.status(200).json({
              token: jwtToken,
              expiresIn: 3600,
              msg: getUser,
            });
          })
          .catch((err) => {
            return res.status(401).json({
              message: 'Authentication failed',
            });
          });
      });

      router.post(
        '/register-user',
        [
          check('name')
            .not()
            .isEmpty()
            .isLength({ min: 4 })
            .withMessage('Name must be atleast  characters long'),
          check('email', 'Email is not valid').not().isEmpty().isEmail(),
          check('password', 'Password should be between 5 to 8 characters long')
            .not()
            .isEmpty()
            .isLength({ min: 5, max: 8 }),
        ],
        (req, res, next) => {
          const errors = validationResult(req);
          if (!errors.isEmpty()) {
            return res.status(422).json(errors.array());
          } else {
            bcrypt.hash(req.body.password, 10).then((hash) => {
              const user = new userSchema({
                name: req.body.name,
                email: req.body.email,
                password: hash,
              });
              user
                .save()
                .then((response) => {
                  res.status(201).json({
                    message: 'User successfully created!',
                    result: response,
                  });
                })
                .catch((error) => {
                  res.status(500).json({
                    error: error,
                  });
                });
            });
          }
        }
      );

      module.exports = router;
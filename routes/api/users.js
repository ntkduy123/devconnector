const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');

const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');

const User = require('../../models/User');

router.get('/test', (req, res) => res.json({ msg: 'Users works' }));

router.post('/resgister', async (req, res) => {
    const { errors, isValid } = validateRegisterInput(req.body);
    if (!isValid) {
        return res.status(400).json(errors);
    }

    const user = await User.findOne({ email: req.body.email });
    if (user) {
        return res.status(400).json({ email: 'Email already exists' });
    }

    const avatar = gravatar.url(req.body.email, {
        s: '200', // size
        r: 'pg', // Rating
        d: 'mm' // Default
    });

    const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password
    });

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser.save()
                .then(user => res.json(user))
                .catch(err => console.log(err));
        });
    });
});

router.post('/login', async (req, res) => {
    const { errors, isValid } = validateLoginInput(req.body);
    if (!isValid) {
        return res.status(400).json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({email: 'User not found'});
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
        const payload = { id: user.id, name: user.name, avatar: user.avatar };
        
        jwt.sign(payload, keys.secretOrKey, { expiresIn: 3600 }, (err, token) => {
            return res.json({
                success: true,
                token: 'Bearer ' + token
            });
        });
    }
    else {
        return res.status(400).json({ password: 'Password incorrect' });
    }
});

router.get('/current', passport.authenticate('jwt', { session: false }), (req, res) => {
    return res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email
    });
});

module.exports = router;